from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
import uuid
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
from django.core.validators import RegexValidator
from decouple import config
from django.core.exceptions import ValidationError

ALLOWED_EXCERCISE_CHOICES = [
                ['yoga', 'Yoga'],
                ['weight_lifting', 'Weight-Lifting'],
                ['cycling', 'Cycling'],
                ['running', 'Running'],
                ['pilates', 'Pilates'],
                ['boxing', 'Boxing'],
                ['aerobics', 'Aerobics'],
                ['other', 'Other']
            ]

ALLOWED_GOALS_CHOICES = [
                ['general_health_monitoring', 'General Health Monitoring'],
                ['health_information_storage', 'Health Information Storage'],
                ['chronic_condition_monitoring', 'Chronic Condition Monitoring'],
                ['preventive_health_management', 'Preventive Health Management'],
                ['diagnostic_test_recommendations', 'Diagnostic Test Recommendations']
            ]

phone_regex = RegexValidator(
    regex=r'^\+1?\d{1,8}\d{4,20}$',
    message='Enter a valid phone number in the format: +91XXXXXXXXXX'
)

PASSWORD_RESET_TOKEN_EXPIRY_DAYS = int(config('PASSWORD_RESET_TOKEN_EXPIRY_DAYS'))

def dynamic_upload_path(instance, filename):
    """
    Generate a dynamic upload path for files.

    Args:
        instance: The model instance associated with the file.
        filename: The original filename of the uploaded file.

    Returns:
        str: A unique path for storing the file in the format:
             "{folder_prefix}_{model_name}/{uuid}_{filename}"
    """

    folder_prefix = config('S3_BUCKET_FOLDER_PREFIX')
    model_name = instance.__class__.__name__.lower()
    return f"{folder_prefix}_{model_name}/{uuid.uuid4()}_{filename}"


class UserManager(BaseUserManager):
    """
    Custom manager for the User model that provides methods for creating users and superusers.

    This manager is used to handle the creation of regular users and superusers, with custom behavior for
    setting the email, password, and additional fields.

    Methods:
        create_user(email, password=None, **extra_fields):
            Creates and returns a regular user with the specified email and password.

        create_superuser(email, password=None, **extra_fields):
            Creates and returns a superuser with the specified email, password, and additional fields 
            (is_staff, is_superuser, and is_active set to True by default).
    """
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        # Make sure is_active is also set to True
        extra_fields.setdefault('is_active', True)

        return self.create_user(email, password, **extra_fields)


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
        
    Methods:
        __str__():
            Returns the string representation of the user, which is the email address.
        
        save(*args, **kwargs):
            Custom save method that ensures the email is stored in lowercase and generates
            a unique `user_id` if it doesn't exist.
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

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        """
        Custom save method to normalize email and generate a unique user ID.

        - Converts the email field to lowercase before saving to maintain consistency.
        - Automatically generates a unique `user_id`:
           - If no `user_id` exists, it starts with 'BHU000001'.
           - If other users exist, it increments the last assigned ID by 1, ensuring 
             that the `user_id` is unique and sequential.

        Args:
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.
        """

        self.email = self.email.lower()
        if not self.user_id:
            last_user = User.objects.filter(user_id__startswith='BHU').order_by('-user_id').first()
            if last_user:
                last_id = int(last_user.user_id[3:])
                new_id = f"BHU{last_id + 1:06d}"
            else:
                new_id = "BHU000001"
            self.user_id = new_id
        super().save(*args, **kwargs)


# Custom validators to check for allowed values
def validate_exercise(value):
    """
    Validates that the provided value is a list of valid exercises.

    This function checks if the input is a list and verifies that each 
    item in the list matches one of the allowed exercise choices defined 
    in `ALLOWED_EXERCISE_CHOICES`. If the input is not a list or contains 
    invalid exercises, it raises a `ValidationError`.

    Args:
        value (list): The input value to validate. It should be a list of exercises.

    Raises:
        ValidationError: If the input is not a list or contains exercises 
        not included in the allowed choices.
    """

    if not isinstance(value, list):  # Ensure the JSON is a list
        raise ValidationError("Exercises should be a list of values.")
    
    allowed_choices = []
    for choice in ALLOWED_EXCERCISE_CHOICES:
        allowed_choices.append(choice[0])
    
    # Check if all values in the list are valid
    invalid_exercise = [excercise for excercise in value if excercise not in allowed_choices]
    
    if invalid_exercise:
        raise ValidationError(f"Invalid exercises: {invalid_exercise}. Allowed choices are: {allowed_choices}")
    

def validate_goals(value):
    """
    Validates that the provided value is a list of valid goals.

    This function checks if the input is a list and verifies that each 
    item in the list matches one of the allowed goal choices defined 
    in `ALLOWED_GOALS_CHOICES`. If the input is not a list or contains 
    invalid goals, it raises a `ValidationError`.

    Args:
        value (list): The input value to validate. It should be a list of goals.

    Raises:
        ValidationError: If the input is not a list or contains goals 
        not included in the allowed choices.

    """

    if not isinstance(value, list):  # Ensure the JSON is a list
        raise ValidationError("Goals should be a list of values.")
    
    allowed_choices = []
    for choice in ALLOWED_GOALS_CHOICES:
        allowed_choices.append(choice[0])
    
    # Check if all values in the list are valid
    invalid_goals = [goal for goal in value if goal not in allowed_choices]
    
    if invalid_goals:
        raise ValidationError(f"Invalid exercises: {invalid_goals}. Allowed choices are: {allowed_choices}")


class PersonalInfo(models.Model):
    GENDER_CHOICES = (
        ('male', 'Male'),
        ('female', 'Female'),
        ('female_to_male', 'Female-to-Male'),
        ('male_to_female', 'Male-to-Female')
    )

    EXCERCISE_TIME_CHOICES = (
        ('15_minutes', '15 Minutes'),
        ('30_minutes', '30 Minutes'),
        ('45_minutes', '45 Minutes'),
        ('1_hour', '1 Hour'),
        ('more_than_1_hour', 'More than 1 Hour'),
    )
    EXERCISE_FREQUENCY_CHOICES = [
        ('1-3_times_per_week', '1-3 times per week'),
        ('4-5_times_per_week', '4-5 times per week'),
        ('6-7_times_per_week', '6-7 times per week'),
        ('occasionally', 'Occasionally'),
        ('never', 'Never'),
    ]
    CURRENT_HEALTH_CHOICES = [
        ('very_unhealthy', 'Very Unhealthy'),
        ('unhealthy', 'Unhealthy'),
        ('average', 'Average'),
        ('healthy', 'Healthy'),
        ('very_healthy', 'Very Healthy'),
    ]
    INTENSITY_OF_EXCERCISE_CHOICES = [
        ('very_light_exercise', 'Very Light Exercise'),
        ('light_exercise', 'Light Exercise'),
        ('moderate_exercise', 'Moderate Exercise'),
        ('intense_exercise', 'Intense Exercise'),
        ('very_intense_exercise', 'Very Intense Exercise'),
    ]
    SYMPTOM_CHOICES = [
        ('sore_throat', 'Sore throat'),
        ('headache', 'Headache'),
        ('cough', 'Cough'),
        ('fever', 'Fever'),
        ('fatigue', 'Fatigue'),
        ('shortness_of_breath', 'Shortness of breath'),
        ('chest_pain', 'Chest pain'),
        ('dizziness', 'Dizziness'),
        ('nausea', 'Nausea'),
        ('muscle_aches', 'Muscle aches'),
        ('joint_pain', 'Joint pain'),
        ('other', 'Other'),

    ]

    """
    Model representing personal information for a user.

    Attributes:
        id (UUIDField): Unique identifier for the personal info record, automatically generated as a UUID.
        gender (CharField, optional): The gender of the user, selected from predefined choices.
        birth_date (DateField, optional): The birth date of the user.
        zip_code (CharField, optional): The zip code of the user's residence.
        feet (CharField, optional): The user's height in feet.
        inches (CharField, optional): The user's height in inches.
        weight (CharField, optional): The user's weight.
        insurance_company_name (CharField, optional): The name of the user's insurance company.
        insurance_no (CharField, optional): The insurance number of the user.
        sponsor_name (CharField, optional): The name of the user's sponsor.
        photo (FileField, optional): A file upload for the user's photo.
        file_name (CharField, optional): Name of the uploaded file.
        is_smoker (BooleanField, optional): Indicates if the user is a smoker.
        exercise_frequency (CharField, optional): Frequency of exercise, selected from predefined choices.
        excercise_activities (JSONField, optional): JSON field containing details of exercise activities.
        excercise_time (CharField, optional): Duration of exercise, selected from predefined choices.
        goal (JSONField, optional): JSON field containing the user's health or fitness goals.
        current_health (CharField, optional): The user's current health status, selected from predefined choices.
        intensity_of_excercise (CharField, optional): The intensity of the user's exercise routine.
        symptom (CharField, optional): The symptoms experienced by the user, selected from predefined choices.
        user (ForeignKey, optional): Reference to the associated user.
        created_at (DateTimeField): The date and time when the record was created.
        updated_at (DateTimeField): The date and time when the record was last updated.
        deleted_at (DateTimeField, optional): The date and time when the record was soft-deleted.

    Methods:
        __str__():
            Returns the string representation of the personal info, which is the UUID of the record.
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    gender = models.CharField(max_length=15, choices=GENDER_CHOICES, null=True, blank=True)
    birth_date = models.DateField(null=True, blank=True)
    zip_code = models.CharField(max_length=50, null=True,  blank=True)
    feet = models.CharField(max_length=50, null=True,  blank=True)
    inches = models.CharField(max_length=50, null=True,  blank=True)
    weight = models.CharField(max_length=50, null=True, blank=True)
    insurance_company_name = models.CharField(max_length=100, blank=True)
    insurance_no = models.CharField(max_length=50, null=True, blank=True)
    sponsor_name = models.CharField(max_length=100, null=True, blank=True)
    photo = models.FileField(upload_to=dynamic_upload_path, null=True, blank=True)
    file_name = models.CharField(max_length=120, null=True)
    is_smoker = models.BooleanField(default=None, null=True)
    exercise_frequency = models.CharField(
        max_length=20, choices=EXERCISE_FREQUENCY_CHOICES, null=True, blank=True)
    excercise_activities = models.JSONField(null=True, blank=True, validators=[validate_exercise])
    excercise_time = models.CharField(
        max_length=100, choices=EXCERCISE_TIME_CHOICES, null=True, blank=True)
    goal = models.JSONField(null=True, blank=True, validators=[validate_goals])
    current_health = models.CharField(max_length=100, choices=CURRENT_HEALTH_CHOICES, null=True, blank=True)
    intensity_of_excercise = models.CharField(max_length=100, choices=INTENSITY_OF_EXCERCISE_CHOICES, null=True, blank=True)
    symptom = models.CharField(max_length=100, choices=SYMPTOM_CHOICES, null=True, blank=True)
    user = models.ForeignKey(User, related_name='personal_info',
                             on_delete=models.CASCADE, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return str(self.id)


class PasswordReset(models.Model):

    """
    Model representing a password reset request for a user.

    Attributes:
        token (CharField): The unique token generated for the password reset request.
        created_at (DateTimeField): The date and time when the password reset request was created.
        expires_at (DateTimeField): The date and time when the password reset token will expire.
        user (ForeignKey): Reference to the associated user who requested the password reset.

    Methods:
        save():
            Automatically sets the expiration time for the password reset token if not already set.
        
        __str__():
            Returns the string representation of the password reset token.
    """
     
    token = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    user = models.ForeignKey(User, related_name='password_reset',
                             on_delete=models.CASCADE, null=True, blank=True)

    def save(self, *args, **kwargs):
        """
        Custom save method to set the expiration time for the password reset token.

        If the expiration time is not set, it will be automatically calculated
        based on the current time plus the expiration period defined by 
        PASSWORD_RESET_TOKEN_EXPIRY_DAYS.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        if not self.expires_at:
            self.expires_at = timezone.now(
            ) + timezone.timedelta(days=PASSWORD_RESET_TOKEN_EXPIRY_DAYS)
        super().save(*args, **kwargs)

    def __str__(self):
        return str(self.token)


class MasterSubscriptionPlan(models.Model):

    """
    Model representing a master subscription plan.

    Attributes:
        id (UUIDField): Unique identifier for the subscription plan.
        name (CharField): Name of the subscription plan.
        start_date (DateField): The start date of the subscription plan.
        end_date (DateField): The end date of the subscription plan.
        stripe_id (CharField): The Stripe ID associated with the subscription plan.
        is_active (BooleanField): Flag indicating whether the subscription plan is active.
        is_deleted (BooleanField): Flag indicating whether the subscription plan is deleted.

    Methods:
        __str__():
            Returns the name of the subscription plan as the string representation.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    name = models.CharField(max_length=100)
    start_date = models.DateField(blank=True, null=True)
    end_date = models.DateField(blank=True, null=True)
    stripe_id = models.CharField(max_length=200, null=True, blank=True)
    is_active = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return self.name


class MasterSubscriptionPlanPrice(models.Model):

    """
    Model representing the pricing details for a master subscription plan.

    Attributes:
        id (UUIDField): Unique identifier for the price record.
        subscription_plan (ForeignKey): The associated subscription plan for which the price applies.
        price (DecimalField): The price of the subscription plan.
        frequency_in_months (IntegerField): The frequency of payment, in months (e.g., annual subscription).
        stripe_id (CharField): The Stripe ID associated with the subscription plan price.
        is_active (BooleanField): Flag indicating whether the price is active.
        is_deleted (BooleanField): Flag indicating whether the price record is deleted.

    Methods:
        save():
            Rounds the price to two decimal places before saving the record.
        
        __str__():
            Returns the string representation of the subscription plan price (i.e., the price).

    Choices:
        CHOICES (tuple): Available payment frequency options, currently supporting annual subscription.
    """

    CHOICES = (
        (12, 'Annual'),
    )
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    subscription_plan = models.ForeignKey(MasterSubscriptionPlan, on_delete=models.CASCADE,
                                          related_name='plan_price')
    price = models.DecimalField(
        validators=[MinValueValidator(0.00), MaxValueValidator(9999.99)], decimal_places=2, max_digits=5)
    frequency_in_months = models.IntegerField(choices=CHOICES)
    stripe_id = models.CharField(max_length=200, null=True, blank=True)
    is_active = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        """
        Save the price record after rounding the price to two decimal places.

        This ensures that prices are saved with no more than two decimal places.

        Args:
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.
        """
        self.price = round(self.price, 2)
        super().save(*args, **kwargs)

    def __str__(self):
        """
        Returns the string representation of the subscription plan price.

        The string representation will be the price of the plan.

        Returns:
            str: The price of the subscription plan.
        """
        return str(self.price)


class UserSubscriptions(models.Model):
    """
    Model representing a user's subscription to a particular subscription plan.

    Attributes:
        id (UUIDField): Unique identifier for the subscription record.
        user (ForeignKey): The user associated with the subscription.
        subscription_plan (ForeignKey): The subscription plan linked to this subscription.
        stripe_id (CharField): The subscription ID from Stripe, representing the user's subscription.
        stripe_status (CharField): The status of the subscription in Stripe.
        is_active (BooleanField): Flag indicating if the subscription is currently active.
        is_expired (BooleanField): Flag indicating if the subscription has expired.
        is_deleted (BooleanField): Flag indicating if the subscription is deleted.
        payment_method_deleted (BooleanField): Flag indicating if the payment method associated with the subscription is deleted.
        created_at (DateTimeField): Timestamp when the subscription record was created.
        updated_at (DateTimeField): Timestamp when the subscription record was last updated.
        billing_period_start (DateTimeField): The start date of the billing period.
        billing_period_end (DateTimeField): The end date of the billing period (nullable).
        cancelled_on (DateTimeField): The date when the subscription was cancelled (nullable).
        status (CharField): The current status of the subscription (trial, active, cancelled, or expired).

    Methods:
        __str__():
            Returns a string representation of the subscription, typically the unique ID.
    """

    STATUS_CHOICES = (
        ('trial', 'Trial'),
        ('active', 'Active'),
        ('cancelled', 'Cancelled'),
        ('expired', 'Expired'),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, unique=True)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='subscriptions')
    subscription_plan = models.ForeignKey(
        MasterSubscriptionPlanPrice, on_delete=models.CASCADE, related_name='subscription_plans')
    stripe_id = models.CharField(max_length=200, null=True, blank=True)#subscription id in stripe
    stripe_status = models.CharField(max_length=200, null=True, blank=True)
    is_active = models.BooleanField(default=False)
    is_expired = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    payment_method_deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)
    billing_period_start = models.DateTimeField(auto_now_add=True)
    billing_period_end = models.DateTimeField(null=True, blank=True)
    cancelled_on = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='trial')


    def __str__(self):
        return str(self.id)


class LogStripeWebhook(models.Model):
    """
    Model to log Stripe webhook events for tracking and debugging purposes.

    Attributes:
        id (UUIDField): Unique identifier for the log record.
        created_at (DateTimeField): Timestamp when the webhook event was received.
        stripe_id (CharField): The ID associated with the Stripe event (nullable).
        event_name (CharField): The name of the Stripe event (nullable).
        stripe_response (JSONField): The full response from Stripe for the event (nullable).
    
    Methods:
        __str__():
            Returns a string representation of the log record, typically the unique ID.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    stripe_id = models.CharField(max_length=200, null=True, blank=True)
    event_name = models.CharField(max_length=200, null=True, blank=True)
    stripe_response = models.JSONField(null=True, blank=True)

    def __str__(self):
        return str(self.id)


class UserLoginActivity(models.Model):
    """
    Model to log user login activities for tracking and security purposes.

    Attributes:
        user_id (CharField): Unique identifier of the user who logged in.
        login_time (DateTimeField): Timestamp when the user logged in.
        user_agent (CharField): The user agent string of the device/browser used for login.
        ip_address (GenericIPAddressField): The IP address from which the user logged in (nullable).

    Methods:
        __str__():
            Returns a string representation of the login activity in the format:
            "<user_id> logged in at <login_time>".
    """
    user_id = models.CharField(max_length=100)
    login_time = models.DateTimeField(auto_now_add=True)
    user_agent = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    def __str__(self):
        return f"{self.user_id} logged in at {self.login_time}"
