import json
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from monitor.models import APIKey, Log, Alert, DetectedSQLInjectionAttempt, LoginDevice
from monitor.sqli_patterns import SQLInjectionDetector

User = get_user_model()

class SQLInjectionDetectorTestCase(TestCase):
    """
    Tests the core SQLInjectionDetector pattern detection and sanitization logic.
    """
    def test_safe_queries(self):
        # Legitimate inputs shouldn't trigger suspicious flags
        safe_inputs = [
            "John Doe",
            "select_item",
            "SELECT id, name FROM products WHERE category = 'books';",
            "2026-06-23",
            "This is a standard search query for a database system."
        ]
        for val in safe_inputs:
            is_suspicious, severity, explanation, matches = SQLInjectionDetector.detect(val)
            self.assertFalse(is_suspicious, f"Expected safe input for: '{val}' but was flagged.")
            self.assertEqual(severity, "low")

    def test_high_severity_patterns(self):
        # Test basic OR boolean injection
        payload = "1' OR 1=1"
        is_suspicious, severity, explanation, matches = SQLInjectionDetector.detect(payload)
        self.assertTrue(is_suspicious)
        self.assertEqual(severity, "high")
        self.assertIn("OR boolean injection", matches)

        # Test stacked queries
        payload_stacked = "SELECT * FROM users; DROP TABLE users"
        is_suspicious, severity, explanation, matches = SQLInjectionDetector.detect(payload_stacked)
        self.assertTrue(is_suspicious)
        self.assertEqual(severity, "high")
        self.assertIn("Stacked query", matches)

    def test_critical_severity_patterns(self):
        # Test schema enumeration
        payload_schema = "SELECT * FROM information_schema.tables"
        is_suspicious, severity, explanation, matches = SQLInjectionDetector.detect(payload_schema)
        self.assertTrue(is_suspicious)
        self.assertEqual(severity, "critical")
        self.assertIn("Schema enumeration", matches)

        # Test time-based blind injection
        payload_time = "SLEEP(5)"
        is_suspicious, severity, explanation, matches = SQLInjectionDetector.detect(payload_time)
        self.assertTrue(is_suspicious)
        self.assertEqual(severity, "critical")
        self.assertIn("Time-based blind injection", matches)

    def test_sanitization(self):
        # Test quote escaping and comment removal
        input_val = "select 'admin' -- comment"
        sanitized = SQLInjectionDetector.sanitize(input_val)
        self.assertEqual(sanitized, "select ''admin''")


class SQLiMiddlewareTestCase(TestCase):
    """
    Tests the SQLInjectionLoggingMiddleware to verify HTTP interception, logging, and blocking.
    """
    def setUp(self):
        self.client = Client()
        # Create a test user for auth checks
        self.user = User.objects.create_user(
            username="testuser",
            password="testpassword",
            email="test@example.com",
            role="viewer"
        )

    def test_safe_request_passes(self):
        # Sending clean GET query parameter should work
        response = self.client.get(reverse('monitor:login'), {'q': 'hello'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Log.objects.count(), 0)
        self.assertEqual(DetectedSQLInjectionAttempt.objects.count(), 0)

    def test_low_severity_allowed_but_logged(self):
        # "LIKE wildcard" is low severity
        response = self.client.get(reverse('monitor:login'), {'q': "LIKE '%abc%'"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Log.objects.count(), 1)
        self.assertEqual(DetectedSQLInjectionAttempt.objects.count(), 1)
        self.assertEqual(Alert.objects.count(), 1)

        attempt = DetectedSQLInjectionAttempt.objects.first()
        self.assertEqual(attempt.severity, "low")
        self.assertIn("LIKE wildcard", attempt.matched_pattern)

    def test_high_severity_blocked_html(self):
        # Standard GET/POST with high severity should be blocked with a 403 HTML page
        response = self.client.get(reverse('monitor:login'), {'q': "1' OR 1=1"})
        self.assertEqual(response.status_code, 403)
        self.assertIn(b"blocked", response.content.lower())
        
        # Verify logs were created
        self.assertEqual(Log.objects.count(), 1)
        self.assertEqual(DetectedSQLInjectionAttempt.objects.count(), 1)
        self.assertEqual(Alert.objects.count(), 1)

    def test_high_severity_blocked_json(self):
        # JSON request should receive a 403 JSON response
        payload = {"query": "1' OR 1=1"}
        response = self.client.post(
            reverse('monitor:login'),
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 403)
        data = json.loads(response.content)
        self.assertEqual(data["status"], "blocked")
        self.assertEqual(data["severity"], "high")

    def test_exempted_paths(self):
        # Paths like /query and /api/validate should allow high severity payloads
        # because they are built specifically to analyze queries.
        self.client.login(username="testuser", password="testpassword")
        
        # /query (QueryAnalysisView)
        response = self.client.post(
            reverse('monitor:query_analysis'),
            {'query': "1' OR 1=1", 'source_context': 'Testing exempt path'}
        )
        self.assertEqual(response.status_code, 200)
        
        # But it should still log to database via View logic
        self.assertTrue(DetectedSQLInjectionAttempt.objects.filter(raw_query="1' OR 1=1").exists())


class ValidateQueryAPITestCase(TestCase):
    """
    Tests the ValidateQueryAPIView endpoint (/api/validate/).
    """
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="apikeyuser",
            password="password",
            email="apikey@example.com",
            role="admin"
        )
        self.api_key, self.raw_api_key = APIKey.create_key(
            name="Test API Key",
            owner=self.user,
        )

    def _auth_headers(self):
        return {
            "HTTP_AUTHORIZATION": f"ApiKey {self.raw_api_key}",
        }

    def test_api_validates_safe_query(self):
        response = self.client.post(
            reverse('monitor:validate_api'),
            data=json.dumps({"query": "SELECT username, email FROM users WHERE id = 1"}),
            content_type="application/json",
            **self._auth_headers()
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertFalse(data["is_suspicious"])
        self.assertFalse(data["should_block"])

    def test_api_validates_malicious_query(self):
        # Critical severity: Time-based blind
        response = self.client.post(
            reverse('monitor:validate_api'),
            data=json.dumps({"query": "SLEEP(5)", "context": "Automated Tests"}),
            content_type="application/json",
            **self._auth_headers()
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data["is_suspicious"])
        self.assertEqual(data["severity"], "critical")
        self.assertTrue(data["should_block"])
        
        # Check that api logged it
        self.assertTrue(DetectedSQLInjectionAttempt.objects.filter(raw_query="SLEEP(5)").exists())

    def test_api_invalid_payload(self):
        response = self.client.post(
            reverse('monitor:validate_api'),
            data="not-a-json-string",
            content_type="application/json",
            **self._auth_headers()
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn("error", data)

    def test_api_requires_api_key(self):
        response = self.client.post(
            reverse('monitor:validate_api'),
            data=json.dumps({"query": "SELECT 1"}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 401)
        data = json.loads(response.content)
        self.assertIn("error", data)


class APIKeyAccessControlTestCase(TestCase):
    """
    Ensures regular admins can only keep one active API key at a time.
    """
    def setUp(self):
        self.client = Client()
        self.admin_user = User.objects.create_user(
            username="limitedadmin",
            password="password123",
            email="limited@example.com",
            role="admin"
        )

    def test_non_superuser_can_only_have_one_active_api_key(self):
        self.client.login(username="limitedadmin", password="password123")

        first_response = self.client.post(
            reverse('monitor:api_keys'),
            {'action': 'create', 'name': 'First key'}
        )
        self.assertEqual(first_response.status_code, 302)
        self.assertEqual(APIKey.objects.filter(owner=self.admin_user).count(), 1)

        second_response = self.client.post(
            reverse('monitor:api_keys'),
            {'action': 'create', 'name': 'Second key'}
        )
        self.assertEqual(second_response.status_code, 302)
        self.assertEqual(APIKey.objects.filter(owner=self.admin_user).count(), 1)

    def test_reveal_without_key_id_redirects_without_crashing(self):
        self.client.login(username="limitedadmin", password="password123")
        response = self.client.post(reverse('monitor:api_keys'), {'action': 'reveal'})
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('monitor:api_keys'))


class AlertResolveTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="analystuser",
            password="password123",
            email="analyst@example.com",
            role="analyst"
        )
        self.alert = Alert.objects.create(
            alert_type="test_alert",
            message="Test alert message",
            severity="high",
            is_resolved=False,
        )

    def test_resolve_alert_marks_it_resolved(self):
        self.client.login(username="analystuser", password="password123")
        response = self.client.post(
            reverse('monitor:alerts'),
            {'action': 'resolve', 'alert_id': str(self.alert.id)}
        )
        self.assertEqual(response.status_code, 302)
        self.alert.refresh_from_db()
        self.assertTrue(self.alert.is_resolved)
        self.assertIsNotNone(self.alert.resolved_at)

    def test_resolve_alert_without_permission_redirects(self):
        user = User.objects.create_user(
            username="vieweruser",
            password="password123",
            email="viewer@example.com",
            role="viewer"
        )
        self.client.login(username="vieweruser", password="password123")
        response = self.client.post(
            reverse('monitor:alerts'),
            {'action': 'resolve', 'alert_id': str(self.alert.id)}
        )
        self.assertEqual(response.status_code, 302)
        self.alert.refresh_from_db()
        self.assertFalse(self.alert.is_resolved)


class UserManagementAccessControlTestCase(TestCase):
    """
    Ensures user management is restricted to super administrators only.
    """
    def setUp(self):
        self.client = Client()
        self.admin_user = User.objects.create_user(
            username="regularadmin",
            password="password123",
            email="regular@example.com",
            role="admin"
        )
        self.superuser = User.objects.create_superuser(
            username="superadmin",
            password="adminpassword",
            email="admin@example.com",
            role=""
        )

    def test_admin_cannot_access_user_management(self):
        self.client.login(username="regularadmin", password="password123")
        response = self.client.get(reverse('monitor:user_management'))
        self.assertEqual(response.status_code, 403)

    def test_superuser_can_access_user_management(self):
        self.client.login(username="superadmin", password="adminpassword")
        response = self.client.get(reverse('monitor:user_management'))
        self.assertEqual(response.status_code, 200)


class LoginDeviceTrackingTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="deviceuser",
            password="devicepass",
            email="device@example.com",
            role="viewer"
        )

    def test_successful_login_creates_device_inventory_entry(self):
        response = self.client.post(
            reverse('monitor:login'),
            {'username': 'deviceuser', 'password': 'devicepass'}
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(LoginDevice.objects.filter(user=self.user).exists())

        device = LoginDevice.objects.get(user=self.user)
        self.assertTrue(device.device_name)
        self.assertEqual(device.login_count, 1)

    def test_device_inventory_page_is_accessible_for_authenticated_users(self):
        self.client.login(username="deviceuser", password="devicepass")
        response = self.client.get(reverse('monitor:device_inventory'))
        self.assertEqual(response.status_code, 200)
