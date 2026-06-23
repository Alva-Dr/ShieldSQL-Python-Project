import json
from datetime import datetime, timedelta
from collections import defaultdict

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
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


class DashboardView(TemplateView):
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

    def get_queryset(self):
        qs = super().get_queryset().select_related("user")
        severity = self.request.GET.get("severity")
        if severity:
            qs = qs.filter(severity=severity)
        search = self.request.GET.get("q")
        if search:
            qs = qs.filter(message__icontains=search)
        return qs

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

        return render(request, self.template_name, {"form": form, "history": history})

    def _get_client_ip(self, request) -> str:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "unknown")


class LoginView(View):
    template_name = "monitor/login.html"

    def get(self, request):
        if request.user.is_authenticated:
            return redirect("monitor:dashboard")
        return render(request, self.template_name, {"form": LoginForm()})

    def post(self, request):
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            messages.success(request, f"Welcome back, {user.display_name or user.username}!")
            next_url = request.GET.get("next") or "monitor:dashboard"
            return redirect(next_url)
        messages.error(request, "Invalid username or password.")
        return render(request, self.template_name, {"form": form})


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

    def get(self, request):
        users = models.User.objects.all().order_by("-created_at")
        return render(request, self.template_name, {"users": users})

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
                (a.matched_pattern or "")[:60],
            ])
        if len(sqli_data) == 1:
            sqli_data.append(["No attempts recorded", "", "", ""])

        sqli_table = Table(sqli_data, colWidths=[100, 80, 60, 200])
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
                (a.message or "")[:80],
            ])
        if len(alert_data) == 1:
            alert_data.append(["No alerts recorded", "", "", ""])

        alert_table = Table(alert_data, colWidths=[100, 80, 60, 200])
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
