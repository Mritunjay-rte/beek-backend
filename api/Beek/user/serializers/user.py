from django.utils import timezone
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework import serializers
from user.models import User, PersonalInfo, MasterSubscriptionPlanPrice, UserSubscriptions
from datetime import datetime
from django.core.validators import RegexValidator
from django.contrib.auth.models import Group
import stripe 
from decouple import config
from rest_framework.exceptions import NotAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

password_regex = r'^(?=.*[A-Z])(?=.*\d)(?=.*[!"#$%&\'()*+,-./:;<=>?@[\\\]^_`{|}~])[A-Za-z\d!"#$%&\'()*+,-./:;<=>?@[\\\]^_`{|}~]{8,}$'

stripe.api_key = config('STRIPE_SECRET')


class UserTokenSerializer(serializers.ModelSerializer):
    """
    Serializer for user data, including group information, used for token generation.

    This serializer is designed to convert a User model instance into a JSON representation, 
    including the user's ID, name, email, and group details. It is typically used for handling 
    user data when generating or validating tokens.

    Fields:
        - `id`: The unique identifier for the user.
        - `name`: The name of the user.
        - `email`: The email address of the user.
        - `group`: A computed field that retrieves the group(s) associated with the user.

    Method:
        - `get_group`: This method computes and returns the group associated with the user.

    """
    group = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "name", "email", "group"]

    def get_group(self, obj):
        group = obj.groups.first()
        if group:
            return group.name
        return None


class LoginTokenSerializer(TokenObtainPairSerializer):
    """
    Serializer for handling user login and token generation.

    This serializer extends the `TokenObtainPairSerializer` to customize the login validation process. 
    It checks the user's account status, verifies if the user has an active subscription, and returns a 
    response containing the JWT token, user data, and additional information such as whether it's the 
    user's first login and if they have an active subscription.

    Methods:
        - `validate`: Validates the login credentials and enriches the response with additional data.

    Fields in the response:
        - `token`: The generated JWT token for the authenticated user.
        - `user`: Serialized user data, including the user's ID, name, and email.
        - `is_first_login`: A boolean indicating whether it's the user's first login.
        - `has_active_subscription`: A boolean indicating whether the user has an active, trial, or cancelled subscription.

    Raises:
        - `NotAuthenticated`: If the user account is deleted or invalid credentials are provided.

    Notes:
        - The `last_login_at` field is updated when the user successfully logs in.
        - The user’s subscription status is checked against the latest subscription record.
    """

    def validate(self, attrs):
        data = super().validate(attrs)
        if self.user.deleted_at:
            raise NotAuthenticated({"detail": "No active account found with the given credentials"})
        user_data = UserTokenSerializer(self.user).data
        is_first_login = True if self.user.last_login_at == None else False
        has_active_subscription = False
        latest_subscription = UserSubscriptions.objects.filter(user=self.user).order_by('-created_at').first()
        if latest_subscription and latest_subscription.status in ['trial','active', 'cancelled']:
            has_active_subscription = True
        response_data = {
            "token": data,
            'user': user_data,
            'is_first_login':is_first_login,
            'has_active_subscription': has_active_subscription
        }

        self.user.last_login_at = datetime.now()

        self.user.save()

        return response_data
    

class RefreshTokenSerializer(TokenRefreshSerializer):
    """
        Serializer for refreshing JWT tokens.

        This serializer extends the `TokenRefreshSerializer` to validate the refresh token and ensure 
        that the associated user exists and has an active, unblocked account with no deletion record.

        Methods:
            - `validate`: Validates the refresh token, checks user status, and returns the new JWT token.

        Fields in the response:
            - `token`: The refreshed JWT token for the authenticated user.

        Raises:
            - `ValidationError`: If the user associated with the refresh token does not exist or is inactive, blocked, or deleted.

        Notes:
            - The `validate` method first checks that the refresh token is valid and then ensures that the user 
            associated with the token is active and not blocked or deleted.
    """
    def validate(self, attrs):
        data = super().validate(attrs)
        refresh_token = RefreshToken(attrs['refresh'])
        user_id = refresh_token['user_id']
        try:
            User.objects.get(id=user_id, is_active=True, is_blocked=False, deleted_at__isnull=True)
        except User.DoesNotExist:
            raise serializers.ValidationError("User does not exist")
        response_data = {
            "token": data
        }
        return response_data
    
        

class SignupSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration (signup).

    This serializer is used for handling the user registration process. It validates the input 
    data, including email and phone number, and creates a new user record in the database.

    Fields:
        - `email`: Required field for the user's email address.
        - `name`: The user's name (optional).
        - `phone_number`: Required field for the user's phone number with validation on its length 
          and format.

    Methods:
        - `validate_phone_number`: Validates the phone number ensuring it has a minimum length of 
          10 characters and a maximum of 17 characters, while allowing certain symbols and digits.
        - `create`: Creates a new user with the provided validated data and assigns them to the 
          'USER' group.
    Notes:
        - The `phone_number` field is validated to ensure it contains only valid characters and 
          adheres to the required length (between 10 to 17 characters).
        - Upon successful registration, the user is assigned to the 'USER' group.
    """
    email = serializers.EmailField(required=True)
    phone_number = serializers.CharField(
        required=True,
        write_only=True,
        validators=[
            RegexValidator(
                regex=r'^[0-9+\-()\s]*$',
                message='Enter a valid phone number'
            )
        ]
    )

    def validate_phone_number(self, value):
        """
        Phone number minimum characters 10, maximum characters 17
        """
        if(len(value) < 10):
            raise serializers.ValidationError("Phone numbers should have minimum 10 characters.")
        if(len(value) > 17):
            raise serializers.ValidationError("Phone numbers should not exceed 17 characters.")
        return value

    class Meta:
        model = User
        fields = ['email', 'name', 'phone_number']

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        group = Group.objects.get(name="USER")
        user.groups.add(group)
        return user


class SetPasswordSerializer(serializers.Serializer):
    """
    Serializer for setting a new password during the password reset process.

    This serializer handles the validation of the new password, token, and other related data 
    provided during the password reset. It ensures that the password meets the required complexity 
    rules and includes additional data such as the reset token and URLs for success and cancel actions.

    Fields:
        - `password`: The new password to be set. It must be at least 8 characters long, contain 
          at least one uppercase letter, and include at least one special character (as per 
          the `password_regex` validator).
        - `token`: The token used to authenticate the password reset request.
        - `success_url`: URL to redirect to upon successful password reset.
        - `cancel_url`: URL to redirect to if the user cancels the password reset process.
        - `subscription_plan_price_id`: UUID representing the subscription plan or pricing 
          associated with the password reset process.

    Notes:
        - The `password` field is validated using a regular expression that ensures the password 
          contains a mix of uppercase letters, lowercase letters, digits, and special characters.
        - The `token` field is required to validate the password reset request.
        - The `subscription_plan_price_id` provides a reference to the specific pricing or 
          subscription plan related to the password reset process.
    """
    password = serializers.CharField(
        write_only=True,
        validators=[
            RegexValidator(
                regex=password_regex,
                message='Password must be at least 8 characters long with at least one capital letter and symbol.'
            )
        ]
    )
    token = serializers.CharField(required=True)
    success_url = serializers.CharField(required=True)
    cancel_url = serializers.CharField(required=True)
    subscription_plan_price_id = serializers.UUIDField(required=True)


class ValidateActivationTokenSerializer(serializers.Serializer):
    """
    Serializer for validating an activation token.

    This serializer is used to accept and validate an activation token during 
    the process of user account activation. The token is typically sent to the 
    user's email during the registration or activation process, and is validated 
    to ensure that it is correct and not expired.

    Fields:
        - `token`: The activation token that is being validated. It is required 
          and should be a string representing the token received by the user.

    Notes:
        - The `token` field is a required field and is expected to be a string.
        - The validation process checks the validity and expiration of the token.
    """
    token = serializers.CharField(required=True)


class EmailSerializer(serializers.Serializer):
    """
    Serializer for handling email input.

    This serializer is used to accept and validate an email address. It is typically
    used for actions such as password resets, email verification, or subscription management,
    where the user provides their email address as part of a request.

    Fields:
        - `email`: A required field that should be a valid email address.
    Notes:
        - The `email` field is validated to ensure it is a correctly formatted email address.
    """
    email = serializers.EmailField(required=True)


class ResetPasswordSerializer(serializers.Serializer):
    """
    Serializer for handling password reset requests.

    This serializer is used to accept and validate the necessary data for resetting a user's password.
    It requires a valid password reset token and the new password. The new password must meet specific
    security requirements as defined by the regex.

    Fields:
        - `token`: A required field representing the password reset token.
        - `new_password`: A required field representing the new password. It must meet specific criteria:
            - At least 8 characters long.
            - Contain at least one uppercase letter.
            - Contain at least one special character or symbol.

    Notes:
        - The `new_password` field will be validated to ensure it follows the defined password strength requirements.
        - The `token` field is used to verify the authenticity of the password reset request.
    """
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(
        write_only=True,
        validators=[
            RegexValidator(
                regex=password_regex,
                message='Password must be at least 8 characters long with at least one capital letter and symbol.'
            )
        ]
    )


class ChangePasswordSerializer(serializers.Serializer):
    """
        Serializer for handling password change requests.

        This serializer is used to accept and validate the necessary data for changing a user's password.
        It requires the new password to meet specific security requirements as defined by the regex.

        Fields:
            - `new_password`: A required field representing the new password. It must meet specific criteria:
                - At least 8 characters long.
                - Contain at least one uppercase letter.
                - Contain at least one special character or symbol.
        Notes:
            - The `new_password` field will be validated to ensure it follows the defined password strength requirements.
    """
    new_password = serializers.CharField(
        write_only=True,
        validators=[
            RegexValidator(
                regex=password_regex,
                message='Password must be at least 8 characters long with at least one capital letter and symbol.'
            )
        ]
    )


class PersonalInfoSerializer(serializers.ModelSerializer):
    """
        Serializer for retrieving and presenting a user's personal information, including their subscription details and status.

        This serializer aggregates user information from the `PersonalInfo` model, including details about the user's
        subscription status, subscription end date, and trial status. It also includes the user's name, email, and
        email notification preference.

        Fields:
            - `id`: The unique identifier of the personal information entry.
            - `zip_code`: The user's postal code.
            - `subscription_details`: A nested serializer containing the details of the user's subscription (if active).
            - `subscription_status`: A dictionary containing the status of the user's subscription, including:
                - `status`: The current status of the subscription ('active', 'cancelled', 'expired', 'pending').
                - `cancelled_on`: The timestamp when the subscription was cancelled (if applicable).
                - `end_date`: The billing period end date of the subscription (if applicable).
                - `is_trial`: A boolean indicating whether the subscription is in trial period.

        Methods:
            - `get_subscription_status`: Retrieves the subscription status, cancellation date, and trial status.
            - `get_subscription_details`: Retrieves detailed subscription information (if active).
            - `to_representation`: Customizes the response to include additional user information like `name`, `email`, and 
            `is_email_notifications_enabled`.

        Notes:
            - The subscription status is dynamically calculated based on the user's most recent subscription.
            - The status is marked as 'pending' for users who have not completed a checkout session.
    """
    subscription_details = serializers.SerializerMethodField()
    subscription_status = serializers.SerializerMethodField()

    def get_subscription_status(self, obj):
        user_subscription = obj.user.subscriptions.filter(is_deleted=False).order_by('created_at').last()
        status = end_date = cancelled_on = is_trial = None
        is_trial = False
        if user_subscription:
            is_trial = True if user_subscription.status in ['trial'] else False
            end_date = user_subscription.billing_period_end
            if user_subscription.status in ['active', 'trial'] and user_subscription.stripe_status in ['active']:
                status = 'active'
            elif user_subscription.status in ['active', 'trial'] and user_subscription.stripe_status in ['inactive']:
                status = 'cancelled'
                cancelled_on = user_subscription.cancelled_on
            elif user_subscription.status in ['expired']:
                status = 'expired'  
                cancelled_on = user_subscription.cancelled_on
        else:
            user_subscription = obj.user.subscriptions.filter(is_deleted=True).order_by('created_at').last()
            if user_subscription:
                status = 'expired'  
                cancelled_on = user_subscription.cancelled_on
                end_date = user_subscription.billing_period_end
                is_trial = True if user_subscription.status in ['trial'] else False
            else:
                # status is set to pending for those who havent done checkout session successfully atleast once
                status = 'pending'

        return {
            'status': status,
            'cancelled_on': cancelled_on.strftime('%Y-%m-%d %H:%M:%S') if cancelled_on else None,
            'end_date': end_date.strftime('%Y-%m-%d %H:%M:%S') if end_date else None,
            'is_trial': is_trial
        }


    def get_subscription_details(self, obj):
        user_subscription = obj.user.subscriptions.filter(is_deleted=False).order_by('created_at').last()
        if user_subscription:
            serializer = UserSubscriptionSerializer(user_subscription)
            return serializer.data
        return None

    class Meta:
        model = PersonalInfo
        fields = ['id', 'zip_code', 'subscription_details', 'subscription_status']

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['name'] = instance.user.name
        data['email'] = instance.user.email
        data['is_email_notifications_enabled'] = instance.user.is_email_notifications_enabled
        return data


class CreateSubscriptionSerializer(serializers.Serializer):
    """
        Serializer for creating a subscription by collecting necessary data such as success URL, cancel URL, and the
        subscription plan price ID.

        This serializer validates the inputs required for initiating a subscription process, which includes the URL
        to redirect to upon success, the URL to redirect to if the subscription process is canceled, and the ID of the
        subscription plan price to be used.

        Fields:
            - `success_url`: The URL to redirect the user to upon successful subscription creation.
            - `cancel_url`: The URL to redirect the user to if the subscription process is canceled.
            - `subscription_plan_price_id`: The unique identifier of the subscription plan price to be used for the subscription.
        Notes:
            - This serializer does not handle the actual creation of the subscription; it only validates and prepares the data.
            - It expects the `subscription_plan_price_id` to be a valid UUID representing the selected subscription plan's price.
    """
    success_url = serializers.CharField(required=True)
    cancel_url = serializers.CharField(required=True)
    subscription_plan_price_id = serializers.UUIDField(required=True)


class SubscriptionSerializer(serializers.ModelSerializer):
    """
    Serializer for representing subscription plan pricing details.

    This serializer is used to transform `MasterSubscriptionPlanPrice` model instances 
    into JSON data. It includes the price and frequency of a subscription plan, along 
    with the associated subscription plan details.

    Fields:
        - `id`: The unique identifier for the subscription plan price.
        - `price`: The price of the subscription plan.
        - `frequency_in_months`: The frequency at which the subscription is billed (in months).
        - `subscription_plan`: The subscription plan associated with the price, represented as a nested object.
    Notes:
        - The `depth` attribute is set to 1, which allows the `subscription_plan` field 
          to be serialized as a nested object, including its related fields.
        - The `subscription_plan` field corresponds to a foreign key relationship 
          between `MasterSubscriptionPlanPrice` and a `SubscriptionPlan` model (or similar).
    """
    class Meta:
        model = MasterSubscriptionPlanPrice
        fields = ['id', 'price', 'frequency_in_months', 'subscription_plan'] 
        depth = 1


class UserSubscriptionSerializer(serializers.ModelSerializer):
    """
        Serializer for representing user subscription details.

        This serializer is used to transform `UserSubscriptions` model instances into 
        JSON data. It includes details of the subscription, such as the subscription 
        plan associated with the user.

        Fields:
            - `id`: The unique identifier for the user subscription.
            - `subscription_plan`: The subscription plan associated with the user, 
            represented as a nested object.

        Notes:
            - The `depth` attribute is set to 1, meaning that the `subscription_plan` field 
            will be serialized as a nested object, including its related fields.
            - The `subscription_plan` field corresponds to a foreign key relationship 
            between `UserSubscriptions` and a `SubscriptionPlan` model (or similar).
    """
    
    class Meta:
        model = UserSubscriptions
        fields = ['id', 'subscription_plan'] 
        depth = 1