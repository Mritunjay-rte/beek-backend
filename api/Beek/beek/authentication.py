from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from decouple import config
from rest_framework import serializers
import redis
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken
from django.conf import settings
from decouple import config
from rest_framework.exceptions import APIException

FREE_TRIAL_PERIOD_IN_DAYS=int(config('FREE_TRIAL_PERIOD_IN_DAYS'))


class CustomAPIException(APIException):
    """
    Custom exception class to handle specific API error scenarios in Django REST Framework.

    Attributes:
        status_code (int): The HTTP status code to be returned with the error response.
        default_detail (str): The default error message to be returned if no detail is provided.
        default_code (str): A string representing the error code for the exception.
    """
    status_code = 400
    default_detail = "Your account is restricted."
    default_code = "account_restricted"

class UserAuthenticationBackend(ModelBackend):
    """
    Custom authentication backend to check if the user is not deleted (deleted_at is None).
    """

    def authenticate(self, request, email=None, password=None, **kwargs):
        User = get_user_model()
        try:
            # Check if the username or email is being used to authenticate
            if email is not None:
                user = User.objects.get(email=email.lower())
            elif 'username' in kwargs: 
                # Fall back to username for admin login
                user = User.objects.get(email=kwargs['username'])

            # Check password and user status
            if user.check_password(password) and user.is_active and not user.is_blocked and user.deleted_at is None:
                return user
            if user.is_blocked:
                raise CustomAPIException(detail="Your account is restricted.")

        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        User = get_user_model()
        try:
            user = User.objects.get(pk=user_id)
            if user.is_active and user.deleted_at is None and not user.is_blocked:
                return user
            return None
        except User.DoesNotExist:
            return None


class BeekJWTAuthentication(BaseAuthentication):
    def __init__(self):
        # Initialize Redis client with environment configuration
        self.redis_client = redis.StrictRedis(
            host=config('WS_REDIS_HOST'), 
            port=config('WS_REDIS_PORT'), 
            password=config('WS_REDIS_PASSWORD'), 
            db=0,
            ssl=config('WS_REDIS_SSL', default='False').lower() in ('true', '1'),
            ssl_cert_reqs=None
        )

    def authenticate(self, request):

        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None  # No token found in the request headers
        
        # Extract token from header (Bearer <token>)
        try:
            token = auth_header.split(" ")[1]
        except IndexError:
            raise AuthenticationFailed("Invalid token header format.")

        # Check Redis to see if the token is blacklisted
        if self.redis_client.get(f"blacklist_{token}") == b"blacklisted":
            raise AuthenticationFailed("Token has been expired. Please log in again.")

        # Validate token if it's not blacklisted
        try:
            access_token = AccessToken(token)
            user = get_user_model().objects.get(id=access_token["user_id"])

            if user.is_blocked or user.deleted_at:
                reason = "blocked" if user.is_blocked else "marked for deletion"
                raise AuthenticationFailed(f"Your account is currently {reason}.")

            return user, token

        except get_user_model().DoesNotExist:
            raise AuthenticationFailed("Token validation error: User does not exist.")
        except Exception as e:
            raise AuthenticationFailed(f"Authentication failed: {str(e)}")

