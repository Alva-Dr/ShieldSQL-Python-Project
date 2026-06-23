import logging
from typing import Dict, Any

from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from django.contrib.auth import get_user_model

from .models import Log, DetectedSQLInjectionAttempt
from .sqli_patterns import SQLInjectionDetector

logger = logging.getLogger(__name__)

User = get_user_model()


class SQLInjectionLoggingMiddleware(MiddlewareMixin):
    """
    Intercepts incoming requests, inspects parameters for SQL injection patterns,
    logs findings, and stores detected attempts in the database.
    """

    def __init__(self, get_response=None):
        self.get_response = get_response
        super().__init__(get_response)

    def _get_client_ip(self, request) -> str:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR", "unknown")
        return ip

    def _get_user(self, request):
        if request.user.is_authenticated:
            return request.user
        return None

    def _inspect_value(self, value: str) -> Dict[str, Any]:
        """Return detection result for a single string value."""
        is_suspicious, severity, explanation, matched_patterns = (
            SQLInjectionDetector.detect(value)
        )
        return {
            "is_suspicious": is_suspicious,
            "severity": severity,
            "explanation": explanation,
            "matched_patterns": matched_patterns,
        }

    def _check_list(self, items: list, prefix: str = "") -> list:
        findings = []
        if not items:
            return findings
        for idx, item in enumerate(items):
            if isinstance(item, str):
                result = self._inspect_value(item)
                if result["is_suspicious"]:
                    result["param"] = f"{prefix}[{idx}]"
                    findings.append(result)
        return findings

    def _check_dict(self, data: dict, prefix: str = "") -> list:
        findings = []
        if not data:
            return findings
        for key, value in data.items():
            param_name = f"{prefix}{key}" if not prefix else f"{prefix}.{key}"
            if isinstance(value, str):
                result = self._inspect_value(value)
                if result["is_suspicious"]:
                    result["param"] = param_name
                    findings.append(result)
            elif isinstance(value, list):
                findings.extend(self._check_list(value, param_name))
            elif isinstance(value, dict):
                findings.extend(self._check_dict(value, param_name))
        return findings

    def process_request(self, request):
        findings = []
        params_to_check: Dict[str, Any] = {}

        if request.method in ("GET",):
            params_to_check = dict(request.GET)
        elif request.method in ("POST", "PUT", "PATCH", "DELETE"):
            # Combine POST body, FILES, and GET params
            post_data = {k: v for k, v in request.POST.items()}
            json_body = {}
            if hasattr(request, "body") and request.body:
                try:
                    import json
                    body_str = request.body.decode("utf-8", errors="ignore")
                    if body_str.strip().startswith("{") or body_str.strip().startswith("["):
                        json_body = json.loads(body_str)
                except (ValueError, UnicodeDecodeError):
                    pass
            params_to_check = {**post_data, **json_body}

        # Flatten and check
        flat_params: Dict[str, str] = {}
        for key, value in params_to_check.items():
            if isinstance(value, (list, tuple)):
                flat_params[key] = ", ".join(
                    str(v) for v in value if isinstance(v, (str, int, float))
                )
            else:
                flat_params[key] = str(value) if value is not None else ""

        for key, val in flat_params.items():
            result = self._inspect_value(val)
            if result["is_suspicious"]:
                result["param"] = key
                findings.append(result)

        if not findings:
            return None

        ip = self._get_client_ip(request)
        user = self._get_user(request)
        now = timezone.now()
        method = request.method
        path = request.get_full_path()

        # Determine top severity
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        top_severity = max(findings, key=lambda f: severity_order.get(f["severity"], 0))["severity"]

        level = "info"
        if top_severity == "medium":
            level = "warning"
        elif top_severity in ("high", "critical"):
            level = "error"

        # Log every individual finding
        for f in findings:
            log_message = (
                f"SQL Injection pattern detected in parameter '{f['param']}': "
                f"{f['explanation']} [severity={f['severity']}] | method={method} path={path}"
            )
            Log.objects.create(
                level=level,
                message=log_message,
                source_ip=ip,
                metadata={
                    "parameter": f["param"],
                    "severity": f["severity"],
                    "matched_patterns": f["matched_patterns"],
                    "method": method,
                    "path": path,
                    "user_id": user.pk if user else None,
                },
            )

        # Store a consolidated DetectedSQLInjectionAttempt
        top_finding = max(findings, key=lambda f: severity_order.get(f["severity"], 0))
        attempt = DetectedSQLInjectionAttempt.objects.create(
            timestamp=now,
            raw_query=flat_params.get(top_finding["param"], ""),
            source_ip=ip,
            matched_pattern="; ".join(top_finding["matched_patterns"]),
            severity=top_severity,
            metadata={
                "all_findings": [
                    {
                        "param": f["param"],
                        "severity": f["severity"],
                        "matched_patterns": f["matched_patterns"],
                    }
                    for f in findings
                ],
                "method": method,
                "path": path,
                "user_id": user.pk if user else None,
            },
        )

        # Create a corresponding Alert
        from .models import Alert

        Alert.objects.create(
            alert_type="sqli_detection",
            message=f"SQL Injection detected on {method} {path} from {ip}. "
                    f"Severity: {top_severity.upper()}. Pattern: {top_finding['explanation']}",
            severity=top_severity,
            user=user if user and user.is_authenticated else None,
            metadata={
                "attempt_id": attempt.pk,
                "parameter": top_finding["param"],
                "source_ip": ip,
                "method": method,
                "path": path,
                "matched_patterns": top_finding["matched_patterns"],
            },
        )

        logger.warning(
            "[ShieldSQL] SQLi blocked | severity=%s | param=%s | ip=%s | path=%s",
            top_severity,
            top_finding["param"],
            ip,
            path,
        )

        return None
