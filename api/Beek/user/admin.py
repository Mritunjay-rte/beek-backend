# from django.contrib import admin
# from .models import User

# admin.site.register(User)

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django import forms
from .models import (User, PersonalInfo, PasswordReset, PersonalInfo, MasterSubscriptionPlan, MasterSubscriptionPlanPrice,
                     UserSubscriptions, LogStripeWebhook, UserLoginActivity)


# Custom form for creating new users


class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ('email', 'name', 'is_active',
                  'is_staff', 'is_superuser', 'groups')

# Custom form for changing user details


class CustomUserChangeForm(UserChangeForm):
    class Meta:
        model = User
        fields = ('email', 'name', 'password', 'is_active',
                  'is_staff', 'is_superuser', 'groups')

# Custom UserAdmin


class UserAdmin(BaseUserAdmin):
    form = CustomUserChangeForm
    add_form = CustomUserCreationForm

    list_display = ('user_id', 'email', 'name', 'is_email_verified', 'last_login')
    list_filter = ('is_staff', 'is_active')
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('name','user_id', 'phone_number','stripe_id', 'activation_token')}),
        ('Permissions', {'fields': ('is_staff','is_email_verified','is_email_notifications_enabled',
         'is_superuser', 'is_active','is_blocked', 'groups')}),
        ('Important dates', {'fields': ('last_login_at','activation_token_created_on','deleted_at')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'name', 'password1', 'password2', 'groups'),
        }),
    )
    search_fields = ('email', 'name', 'user_id')
    ordering = ('email',)
    # Enables horizontal filter widget for groups
    filter_horizontal = ('groups',)

class UserSubscriptionsAdmin(admin.ModelAdmin):
    list_display = ('id','user')


admin.site.register(User, UserAdmin)
# admin.site.register(User)
admin.site.register(PersonalInfo)
admin.site.register(PasswordReset)
admin.site.register(MasterSubscriptionPlan)
admin.site.register(MasterSubscriptionPlanPrice)
admin.site.register(UserSubscriptions,UserSubscriptionsAdmin)
admin.site.register(LogStripeWebhook)


class UserLoginActivityAdmin(admin.ModelAdmin):
    list_display = ('user_id', 'login_time', 'user_agent', 'ip_address')
    search_fields = ('user_id', 'user_agent', 'ip_address')


admin.site.register(UserLoginActivity, UserLoginActivityAdmin)
