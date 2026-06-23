from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings


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
