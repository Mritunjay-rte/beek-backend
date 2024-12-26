
from rest_framework import serializers
from user.models import User
from health.models import ExternalAPILog
from datetime import timedelta
from django.utils import timezone


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for User model, including additional computed fields for user status and subscription status.

    This serializer provides details about a user, including their subscription status, user status, and other account information.
    The following computed fields are included:
    - `subscription_status`: The current status of the user's subscription (e.g., 'Active', 'Trial', 'Expired', 'Terminated', 'Pending').
    - `user_status`: The current status of the user account (e.g., 'Active', 'Inactive', 'Restricted', 'Deleted').

    Fields:
        - `id`: Unique identifier for the user.
        - `user_id`: The user ID.
        - `name`: The name of the user.
        - `email`: The user's email address.
        - `is_active`: Boolean indicating if the user is active.
        - `created_at`: Timestamp when the user was created.
        - `subscription_status`: The status of the user's subscription (computed field).
        - `user_status`: The status of the user account (computed field).
        - `phone_number`: The user's phone number.
        - `last_login_at`: Timestamp of the user's last login.

    Methods:
        - `get_subscription_status(obj)`: Returns the current status of the user's subscription based on the latest subscription.
            - If no subscription exists or the user is terminated, it returns 'Pending' or 'Terminated'.
            - If the latest subscription is a trial, it returns 'Trial'.
            - If the subscription is expired, it returns 'Expired'.
            - If the subscription is active or cancelled, it returns 'Active'.
        - `get_user_status(obj)`: Returns the current status of the user account.
            - If the user is deleted, it returns 'Deleted'.
            - If the user is blocked, it returns 'Restricted'.
            - If the user has logged in within the last 30 days, it returns 'Active'.
            - Otherwise, it returns 'Inactive'.

    Raises:
        - None: This serializer does not raise any specific exceptions during validation.
    """

    subscription_status = serializers.SerializerMethodField()
    user_status = serializers.SerializerMethodField()

    def get_subscription_status(self, obj):
        if obj.deleted_at is not None:
            return "Terminated"
        latest_subscription = obj.subscriptions.all().order_by('created_at').last()
        if latest_subscription:
            if latest_subscription.status == 'trial':
                return "Trial"
            elif latest_subscription.status == 'expired':
                return "Expired"
            elif latest_subscription.status in ['active', 'cancelled']:
                return "Active"
        return "Pending"
        
    
    def get_user_status(self, obj):
        if obj.deleted_at is not None:
            return "Deleted"
        if obj.is_blocked:
            return "Restricted"
        if obj.last_login_at:
            if obj.last_login_at >= timezone.now() - timedelta(days=30):
                return "Active"
        return "Inactive"
    
    class Meta:
        model = User
        fields = ['id', 'user_id', 'name', 'email', 'is_active', 'created_at',
                  'subscription_status', 'user_status', 'phone_number', 'last_login_at']


class UserAccountSerializer(serializers.ModelSerializer):
    """
    Serializer for validating and retrieving user account details by user ID.

    This serializer validates the provided user ID and checks whether the user exists in the database.
    It only returns the user's `id` field. If the user with the provided ID does not exist, it raises a validation error.

    Fields:
        - `id`: The unique identifier of the user, required for validation.

    Methods:
        - `validate_id(value)`: Validates the provided `id` value by checking if a user with the given ID exists in the database.
            - If the user exists, the method returns the ID.
            - If the user does not exist, it raises a `ValidationError` with a message indicating the user was not found.
    Raises:
        - `ValidationError`: If the provided `id` does not correspond to an existing user.
    """
    id = serializers.CharField(max_length=100, required=True)

    class Meta:
        model = User
        fields = ['id']

    def validate_id(self, value):
        try:
            user = User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User does not exist.")

        self.user = user
        return value



class UserReportListSerializer(serializers.ModelSerializer):
    """
    Serializer for generating user report details.

    This serializer converts a `User` model instance into a structured report format, including user details
    and subscription billing period information.

    Fields:
        - `id`: The unique identifier of the user.
        - `user_id`: The user’s ID.
        - `name`: The user's name.
        - `email`: The user's email address.
        - `phone_number`: The user's phone number.
        - `created_at`: The timestamp when the user was created.
        - `subscription_status`: The current subscription status of the user (e.g., 'active', 'inactive', 'expired').
        - `last_login_at`: The timestamp of the user's last login.
        - `billing_period_start`: The start date of the user's billing period.
        - `billing_period_end`: The end date of the user's billing period.

    Notes:
        - The `billing_period_start` and `billing_period_end` fields are nullable and may be `null` if not available.
        - This serializer is used for generating reports of user accounts, including their subscription details.
    """
    subscription_status = serializers.CharField()
    billing_period_start = serializers.DateTimeField(allow_null=True)
    billing_period_end = serializers.DateTimeField(allow_null=True)

    class Meta:
        model = User
        fields = [
            'id', 'user_id', 'name', 'email', 'phone_number', 'created_at',
            'subscription_status', 'last_login_at', 'billing_period_start',
            'billing_period_end'
        ]

    
class UserAPIUsageReportListSerializer(serializers.ModelSerializer):
    """
    Serializer for representing the API usage report for users.

    This serializer converts a `User` model instance into a structured report format, including details about
    the user's API usage, the providers they are connected to, and their subscription status.

    Fields:
        - `id`: The unique identifier of the user.
        - `user_id`: The user’s ID.
        - `email`: The user's email address.
        - `name`: The user's name.
        - `provider_count`: The number of API providers connected to the user.
        - `total_api_calls`: The total number of API calls made by the user.
        - `initial_api_calls`: The number of initial API calls made by the user.
        - `refresh_api_calls`: The number of refresh API calls made by the user.
        - `last_api_call`: The timestamp of the last API call made by the user.
        - `last_login_at`: The timestamp of the user’s last login.
        - `provider_names`: A list of names of the API providers connected to the user.
        - `user_status`: The current status of the user’s subscription.
        - `get_provider_names`: Retrieves the list of provider names connected to the user.

    Notes:
        - The `provider_names` field is dynamically fetched using the `get_provider_names` method.
        - The `last_api_call` field can be `null` if the user has not made any API calls yet.
        - This serializer is used for generating user-specific API usage reports for administrative purposes.
    """
    provider_names = serializers.SerializerMethodField()
    provider_count = serializers.IntegerField()
    total_api_calls = serializers.IntegerField()
    initial_api_calls = serializers.IntegerField()
    refresh_api_calls = serializers.IntegerField()
    last_api_call = serializers.DateTimeField(allow_null=True)
    user_status = serializers.CharField()

    def get_provider_names(self, obj):
        return obj.provider_names or []
    class Meta:
        model = User
      
        fields = [
            'id', 'user_id', 'email', 'name','provider_count','total_api_calls','initial_api_calls',
              'refresh_api_calls', 'last_api_call', 'last_login_at', 'provider_names', 'user_status'
        ]


class UserAPIUsageDetailsListSerializer(serializers.ModelSerializer):
    """
    Serializer for serializing details of API usage details related to a user.

        This serializer takes an `ExternalAPILog` instance and serializes it into a representation suitable for
        API responses. It includes the API endpoint, the timestamp of the request, the status of the response, 
        and any error message if the request failed.

        Fields:
            - `id`: The unique identifier of the API log entry.
            - `api_endpoint`: The API endpoint that was requested.
            - `requested_at`: The timestamp of when the API request was made.
            - `is_success_response`: A boolean indicating whether the API response was successful or not.
            - `error_message`: The error message, if any, returned by the API in case of failure.
            - `status`: A derived field indicating whether the API response was 'Success' or 'Failure', based on the `is_success_response` field.
        Notes:
            - The `status` field is dynamically generated based on the `is_success_response` field, translating `True` to "Success" and `False` to "Failure".
            - This serializer is intended to represent logs of external API calls made by a user and is useful for tracking API usage and debugging errors.
    """
    
    class Meta:
        model = ExternalAPILog
        fields = ['id', 'api_endpoint', 'requested_at', 'is_success_response', 'error_message']
    
    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['status'] = 'Success' if instance.is_success_response else "Failure"
        return data
