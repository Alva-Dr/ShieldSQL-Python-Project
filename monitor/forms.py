from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import get_user_model

from .sqli_patterns import SQLInjectionDetector

User = get_user_model()


class SQLQueryForm(forms.Form):
    query = forms.CharField(
        label="SQL Query",
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 4,
                "placeholder": "Enter a SQL query to analyze...",
                "id": "sqliQueryInput",
            }
        ),
        min_length=1,
        max_length=5000,
        help_text="Submit a query for real-time SQL injection analysis.",
    )
    source_context = forms.CharField(
        label="Context / Application",
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "e.g., Login form, Search field...",
            }
        ),
    )

    def clean_query(self):
        query = self.cleaned_data["query"].strip()
        is_suspicious, severity, explanation, matched_patterns = (
            SQLInjectionDetector.detect(query)
        )
        self.suspicious = is_suspicious
        self.severity = severity
        self.explanation = explanation
        self.matched_patterns = matched_patterns

        if is_suspicious:
            if severity in ("high", "critical"):
                raise forms.ValidationError(
                    f"Potentially malicious input detected ({explanation}). "
                    "This request has been logged and blocked."
                )
        return query

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.suspicious = False
        self.severity = "low"
        self.explanation = ""
        self.matched_patterns = []


class LoginForm(AuthenticationForm):
    username = forms.CharField(
        widget=forms.TextInput(
            attrs={"class": "form-control", "placeholder": "Username", "autofocus": True}
        )
    )
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={"class": "form-control", "placeholder": "Password"}
        )
    )


class RegistrationForm(forms.ModelForm):
    password1 = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "Password"}),
    )
    password2 = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "Confirm Password"}),
    )
    role = forms.ChoiceField(
        choices=[
            ("viewer", "Viewer / User"),
            ("analyst", "Security Analyst"),
            ("admin", "Administrator"),
        ],
        widget=forms.Select(attrs={"class": "form-select"}),
        help_text="Select role. First registered user becomes super admin.",
    )

    class Meta:
        model = User
        fields = ["username", "email", "display_name", "role"]
        widgets = {
            "username": forms.TextInput(attrs={"class": "form-control", "placeholder": "Username"}),
            "email": forms.EmailInput(attrs={"class": "form-control", "placeholder": "Email"}),
            "display_name": forms.TextInput(
                attrs={"class": "form-control", "placeholder": "Display Name"}
            ),
        }

    def clean_password2(self):
        p1 = self.cleaned_data.get("password1")
        p2 = self.cleaned_data.get("password2")
        if p1 and p2 and p1 != p2:
            raise forms.ValidationError("Passwords do not match.")
        return p2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
            # Auto-promote first user to admin with is_superuser
            if User.objects.count() == 1:
                user.role = "admin"
                user.is_superuser = True
                user.is_staff = True
                user.save()
        return user


class UserManagementForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["username", "email", "display_name", "role", "is_active"]
        widgets = {
            "username": forms.TextInput(attrs={"class": "form-control"}),
            "email": forms.EmailInput(attrs={"class": "form-control"}),
            "display_name": forms.TextInput(attrs={"class": "form-control"}),
            "role": forms.Select(attrs={"class": "form-select"}, choices=[
                ("viewer", "Viewer / User"),
                ("analyst", "Security Analyst"),
                ("admin", "Administrator"),
            ]),
            "is_active": forms.CheckboxInput(attrs={"class": "form-check-input"}),
        }
