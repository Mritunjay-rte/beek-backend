from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
import uuid
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
from django.core.validators import RegexValidator

phone_regex = RegexValidator(
    regex=r'^\+1?\d{1,8}\d{4,20}$',
    message='Enter a valid phone number in the format: +91XXXXXXXXXX'
)



class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User model that extends AbstractBaseUser and PermissionsMixin to provide
    authentication and authorization functionality.

    Attributes:
        id (UUIDField): Unique identifier for the user, automatically generated as a UUID.
        name (str): Full name of the user.
        email (EmailField): Unique email address used for authentication.
        is_active (bool): Indicates whether the user's account is active. Default is False.
        is_staff (bool): Indicates whether the user can access the admin interface. Default is False.
        is_superuser (bool): Indicates whether the user has all permissions. Default is False.
        created_at (DateTimeField): The date and time when the user was created.
        updated_at (DateTimeField): The date and time when the user was last updated.
        deleted_at (DateTimeField, optional): The date and time when the user was soft-deleted.
        last_login_at (DateTimeField, optional): The date and time of the user's last login.
        is_blocked (bool): Indicates whether the user is blocked from accessing the system. Default is False.
        is_email_notifications_enabled (bool): Indicates whether email notifications are enabled for the user. Default is True.
        stripe_id (str, optional): Stripe customer ID associated with the user for billing.
        activation_token (str, optional): Unique activation token for email verification.
        activation_token_created_on (DateTimeField, optional): The date and time when the activation token was created.
        phone_number (str, optional): Phone number of the user, validated by a regex.
        is_email_verified (bool): Indicates whether the user's email is verified. Default is False.
        user_id (str, optional): Unique user identifier in the format "BHU######".
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, null=True, blank=True)
    email = models.EmailField(unique=True, max_length=256)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    last_login_at = models.DateTimeField(null=True, blank=True)
    is_blocked = models.BooleanField(default=False)
    is_email_notifications_enabled = models.BooleanField(default=True)
    stripe_id = models.CharField(null=True, blank=True, max_length=200)
    activation_token = models.CharField(
        max_length=120, null=True, blank=True, unique=True)
    activation_token_created_on = models.DateTimeField(blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True,
                                    validators=[phone_regex])
    is_email_verified = models.BooleanField(default=False)
    user_id = models.CharField(
        max_length=10, unique=True, null=True, blank=True
    )

    USERNAME_FIELD = 'email'