from django.contrib import admin
from . import models


@admin.register(models.User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'display_name', 'is_staff', 'created_at')
    search_fields = ('username', 'email', 'display_name')


@admin.register(models.Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('alert_type', 'severity', 'is_resolved', 'user', 'created_at')
    list_filter = ('severity', 'is_resolved')
    search_fields = ('alert_type', 'message')


@admin.register(models.Log)
class LogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'level', 'source_ip', 'user')
    list_filter = ('level',)
    search_fields = ('message', 'source_ip')


@admin.register(models.DetectedSQLInjectionAttempt)
class SQLiAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'source_ip', 'severity', 'user')
    list_filter = ('severity',)
    search_fields = ('raw_query', 'matched_pattern')


@admin.register(models.APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ('name', 'owner', 'is_active', 'created_at', 'last_used')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'owner__username')
    readonly_fields = ('hashed_key', 'created_at', 'last_used')
    fields = ('name', 'owner', 'is_active', 'hashed_key', 'created_at', 'last_used')
