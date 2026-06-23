from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages

ROLE_HIERARCHY = {
    "viewer": 0,
    "analyst": 1,
    "admin": 2,
}

ROLE_CHOICES = {
    "viewer": "Viewer / User",
    "analyst": "Security Analyst",
    "admin": "Administrator",
}


def role_required(min_role: str):
    """
    Decorator for function-based views requiring a minimum role.
    Usage:
        @role_required('analyst')
        def my_view(request): ...
    """
    min_level = ROLE_HIERARCHY.get(min_role, 0)

    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                messages.error(request, "You must be logged in to access this page.")
                return redirect("monitor:login")
            user_level = ROLE_HIERARCHY.get(request.user.role, 0)
            if user_level < min_level:
                raise PermissionDenied(
                    f"Access denied. Required role: {ROLE_CHOICES.get(min_role, min_role)}."
                )
            return view_func(request, *args, **kwargs)
        return wrapped_view
    return decorator


class RoleRequiredMixin(LoginRequiredMixin):
    """
    Mixin for class-based views requiring a minimum role.
    Set `min_role` on the view class (e.g., min_role = 'analyst').
    Unauthenticated users are redirected to login; authenticated users
    without the required role get PermissionDenied (403).
    """
    min_role = "admin"
    login_url = "monitor:login"

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission()
        min_level = ROLE_HIERARCHY.get(self.min_role, 0)
        user_level = ROLE_HIERARCHY.get(getattr(request.user, "role", ""), 0)
        if user_level < min_level:
            messages.error(
                request,
                f"Access denied. Required role: {ROLE_CHOICES.get(self.min_role, self.min_role)}.",
            )
            raise PermissionDenied(
                f"Required role: {ROLE_CHOICES.get(self.min_role, self.min_role)}"
            )
        return super().dispatch(request, *args, **kwargs)
