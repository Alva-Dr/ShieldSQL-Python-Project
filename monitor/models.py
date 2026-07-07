import hashlib
import secrets
from django.core import signing

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.utils import timezone


class User(AbstractUser):
    display_name = models.CharField(max_length=150, blank=True)
    role = models.CharField(max_length=50, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.get_full_name() or self.username


class Alert(models.Model):
    SEVERITY_LOW = 'low'
    SEVERITY_MEDIUM = 'medium'
    SEVERITY_HIGH = 'high'
    SEVERITY_CRITICAL = 'critical'

    SEVERITY_CHOICES = [
        (SEVERITY_LOW, 'Low'),
        (SEVERITY_MEDIUM, 'Medium'),
        (SEVERITY_HIGH, 'High'),
        (SEVERITY_CRITICAL, 'Critical'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name='alerts')
    alert_type = models.CharField(max_length=100)
    message = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default=SEVERITY_MEDIUM)
    is_resolved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(null=True, blank=True)

    def __str__(self):
        return f"{self.alert_type} - {self.severity}"


class Log(models.Model):
    LEVEL_DEBUG = 'debug'
    LEVEL_INFO = 'info'
    LEVEL_WARNING = 'warning'
    LEVEL_ERROR = 'error'
    LEVEL_CRITICAL = 'critical'

    LEVEL_CHOICES = [
        (LEVEL_DEBUG, 'DEBUG'),
        (LEVEL_INFO, 'INFO'),
        (LEVEL_WARNING, 'WARNING'),
        (LEVEL_ERROR, 'ERROR'),
        (LEVEL_CRITICAL, 'CRITICAL'),
    ]

    timestamp = models.DateTimeField(auto_now_add=True)
    level = models.CharField(max_length=10, choices=LEVEL_CHOICES, default=LEVEL_INFO)
    message = models.TextField()
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name='logs')
    metadata = models.JSONField(null=True, blank=True)

    def __str__(self):
        return f"[{self.level}] {self.message[:60]}"


class DetectedSQLInjectionAttempt(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    raw_query = models.TextField()
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name='sqli_attempts')
    matched_pattern = models.TextField(null=True, blank=True)
    severity = models.CharField(max_length=10, choices=Alert.SEVERITY_CHOICES, default=Alert.SEVERITY_HIGH)
    alert = models.ForeignKey(Alert, null=True, blank=True, on_delete=models.SET_NULL, related_name='sqli_attempts')
    metadata = models.JSONField(null=True, blank=True)

    def __str__(self):
        return f"SQLi from {self.source_ip or 'unknown'} at {self.timestamp}"


class LoginDevice(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="login_devices",
    )
    device_name = models.CharField(max_length=120, blank=True)
    user_agent = models.TextField(blank=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    login_count = models.PositiveIntegerField(default=1)
    last_login_at = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["-last_login_at"]

    def __str__(self):
        return f"{self.user.username} @ {self.device_name or 'Unknown device'}"


class APIKey(models.Model):
    name = models.CharField(max_length=120)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="api_keys",
    )
    hashed_key = models.CharField(max_length=64, unique=True, editable=False)
    encrypted_key = models.TextField(null=True, blank=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"API Key {self.name} ({'active' if self.is_active else 'inactive'})"

    @staticmethod
    def generate_raw_key(length: int = 32) -> str:
        return secrets.token_urlsafe(length)

    @staticmethod
    def hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def set_raw_key(self, raw_key: str):
        self.hashed_key = self.hash_key(raw_key)

    @classmethod
    def create_key(cls, name: str, owner=None, is_active: bool = True):
        raw_key = cls.generate_raw_key()
        instance = cls(name=name, owner=owner, is_active=is_active)
        instance.set_raw_key(raw_key)
        try:
            instance.encrypted_key = signing.dumps(raw_key, salt="monitor.apikey.v1")
        except Exception:
            instance.encrypted_key = None
        instance.save()
        return instance, raw_key

    @classmethod
    def verify(cls, raw_key: str):
        if not raw_key or not isinstance(raw_key, str):
            return None
        hashed = cls.hash_key(raw_key.strip())
        return cls.objects.filter(hashed_key=hashed, is_active=True).first()

    def mark_used(self):
        self.last_used = timezone.now()
        self.save(update_fields=["last_used"])

    def reveal_raw_key(self):
        """Return the original raw key when possible (signed)."""
        if not self.encrypted_key:
            return None
        try:
            raw = signing.loads(self.encrypted_key, salt="monitor.apikey.v1")
            return raw
        except signing.BadSignature:
            return None
