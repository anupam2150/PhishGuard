from django.contrib import admin
from .models import UserProfile


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "created_at", "personal_api_key")
    search_fields = ("user__username", "user__email")
    readonly_fields = ("personal_api_key", "created_at")
