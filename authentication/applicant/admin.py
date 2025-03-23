from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth import get_user_model

User = get_user_model()  # Ensure it uses your custom user model

class CustomUserAdmin(UserAdmin):
    list_display = ('reg_number', 'email', 'full_name', 'is_active', 'is_staff', 'is_applicant')
    search_fields = ('reg_number', 'email', 'full_name')
    list_filter = ('is_active', 'is_staff', 'is_applicant')
    ordering = ('reg_number',)

    fieldsets = (
        (None, {'fields': ('reg_number', 'email', 'full_name', 'password')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'is_applicant', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login',)}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('reg_number', 'email', 'full_name', 'password1', 'password2', 'is_active', 'is_staff', 'is_applicant'),
        }),
    )

admin.site.register(User, CustomUserAdmin)  # Use `User` from `get_user_model()`
