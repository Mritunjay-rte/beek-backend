from datetime import timedelta
from django.core.exceptions import ObjectDoesNotExist
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from beek.responses import SuccessResponse, ErrorResponse
from user.utils import send_custom_email
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.generics import GenericAPIView, CreateAPIView, ListAPIView
from django.utils import timezone
from user.serializers import (LoginTokenSerializer, SubscriptionSerializer,
                              SignupSerializer, EmailSerializer, ResetPasswordSerializer, PersonalInfoSerializer,
                              CreateSubscriptionSerializer, SetPasswordSerializer, ChangePasswordSerializer, RefreshTokenSerializer,
                              UserSubscriptionSerializer, ValidateActivationTokenSerializer)
from user.models import User, PasswordReset, PersonalInfo
from rest_framework.permissions import IsAuthenticated
from datetime import datetime
from user.models import (User, PasswordReset,
                         PersonalInfo, MasterSubscriptionPlanPrice, UserSubscriptions, UserLoginActivity, LogStripeWebhook)
from decouple import config
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.db import IntegrityError
import stripe
from drf_yasg.utils import swagger_auto_schema
from django.http import JsonResponse
import pytz
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from user.utils import create_1UP_user, create_checkout_session
from django.db import transaction
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
import redis
from rest_framework_simplejwt.tokens import AccessToken
import hashlib



PASSWORD_RESET_FE_URL = config('PASSWORD_RESET_FE_URL')
EMAIL_VERIFICATION_FE_URL = config('EMAIL_VERIFICATION_FE_URL')
ACTIVATION_TOKEN_EXPIRY_HOURS = int(config('ACTIVATION_TOKEN_EXPIRY_HOURS'))

bad_request_err_msg = "Something went wrong"


class LoginView(TokenObtainPairView):
    """
    View to user login to the system

    Methods:
        post(request): Handles POST requests to create a new access and refresh token.
    """
    serializer_class = LoginTokenSerializer

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Login API", 
        operation_description="""
        This API allows users to authenticate by providing their credentials (email and password).
        The user needs to submit a JSON object with the following fields:
        """,
        operation_id='userLogin',
        tags=["user"],
    )
    def post(self, request, *args, **kwargs):
        """
        Handle POST request for user login.

        This method performs the following steps:
        1. Validates the incoming request data using the serializer.
        2. If validation is successful, logs the user's login activity by saving relevant details
        (user ID, user agent, and IP address) in the `UserLoginActivity` model.
        3. Returns a success response upon successful login.

        Args:
            request (HttpRequest): The incoming HTTP request containing login data.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            SuccessResponse: A response object indicating successful login along with validated data.

        Raises:
            serializers.ValidationError: If the provided data is invalid.

        Notes:
            - The `User-Agent` header is used to capture the user's device/browser information.
            - The IP address is retrieved from the `REMOTE_ADDR` key in the request's `META` attribute.
            - If logging the user's login activity fails, it silently passes without affecting the login process.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            # Save login details to UserLoginActivity model
            user_agent = request.headers.get('User-Agent', 'unknown')
            ip_address = request.META.get('REMOTE_ADDR', None)

            UserLoginActivity.objects.create(
                user_id=serializer.user.id,
                user_agent=user_agent,
                ip_address=ip_address,
            )
        except:
            pass

        return SuccessResponse(message="Successfully logged in", data=serializer.validated_data)
    


class LogoutView(GenericAPIView):
    """
        API view to handle user logout by blacklisting tokens.

        Methods:
        post(request): Handle POST request to log out a user by blacklisting the refresh and access tokens.

    """
    permission_classes = (IsAuthenticated,)
    serializer_class = RefreshTokenSerializer

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Logout API",
        operation_description="""
            This API allows users to log out by invalidating their refresh token.
            The request should include a JSON object with the following field:
            - `refresh` (string): The refresh token issued during authentication.
        """,
        operation_id='logout',
        tags=["user"],
    )

    def post(self, request):
        """
        Handle POST request to log out a user by blacklisting the refresh and access tokens.

        This method performs the following steps:
        1. Retrieves the `refresh` token from the request data and blacklists it using Django's `RefreshToken`.
        2. Extracts the `access` token from the `Authorization` header, if present.
        3. Stores the access token in Redis with an expiration time equal to its remaining validity period,
        effectively blacklisting it for the duration of its lifetime.
        4. Returns a success response upon successful logout or an error response in case of failure.

        Args:
            request (HttpRequest): The incoming HTTP request containing the refresh token and authorization header.

        Returns:
            SuccessResponse: A response object indicating successful logout.
            ErrorResponse: A response object with the error message if an exception occurs.

        Redis Configuration:
            - `WS_REDIS_HOST`: The host of the Redis server.
            - `WS_REDIS_PORT`: The port of the Redis server.
            - `WS_REDIS_PASSWORD`: The password for the Redis server (if applicable).
            - `WS_REDIS_SSL`: Boolean indicating whether to use SSL for the Redis connection.

        Notes:
            - The refresh token is blacklisted using Django's token blacklist feature.
            - The access token is stored in Redis with a key format `blacklist_{token}` and will automatically
            expire after its validity period.
            - If the `Authorization` header is missing or invalid, no access token is blacklisted.
        """
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            auth_header = request.headers.get('Authorization', None)
            token = auth_header.split(" ")[1] if auth_header else None
            
            if token:

                redis_client = redis.StrictRedis(
                    host=config('WS_REDIS_HOST'), 
                    port=config('WS_REDIS_PORT'), 
                    password=config('WS_REDIS_PASSWORD'), 
                    db=0,
                    ssl=config('WS_REDIS_SSL', default='False').lower() in ('true', '1'),
                    ssl_cert_reqs=None
                )
                # Set expiration time to match token's expiration time
                expiration = AccessToken(token).get("exp") - AccessToken(token).get("iat")
                redis_client.setex(f"blacklist_{token}", expiration, "blacklisted")
            return SuccessResponse(message="Logout Successfully")
        except Exception as e:
            return ErrorResponse(message=str(e))


class RefreshTokenView(TokenRefreshView):
    """
    API view to handle the refresh of JWT access tokens.

    This view inherits from `TokenRefreshView` and is used to generate a new access token
    by providing a valid refresh token. It extends the default behavior of Django Rest Framework 
    Simple JWT for token refresh functionality.

    Methods:
        post(request, *args, **kwargs):
            Handles the POST request to refresh the access token.
            Args:
                request (HttpRequest): The incoming request containing the refresh token in the request data.
                *args: Additional positional arguments.
                **kwargs: Additional keyword arguments.
            Returns:
                Response: A response containing a new access token if the refresh token is valid, 
                or an error response if the refresh token is invalid or expired.
    """
    serializer_class = RefreshTokenSerializer

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Refresh Token API",
        operation_description="""
            This API allows users to refresh their authentication token using a valid refresh token.
            The user needs to submit a JSON object with the following field:
            - `refresh` (string): The refresh token issued during the initial authentication.
        """,
        operation_id='refreshToken',
        tags=["user"],
    )

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            return SuccessResponse(message="Token refreshed successfully", data=serializer.validated_data)
        except InvalidToken:
            return ErrorResponse(message="The provided token is invalid or expired.", status_code=status.HTTP_401_UNAUTHORIZED)
        except TokenError as e:
            return ErrorResponse(message=str(e), status_code=status.HTTP_400_BAD_REQUEST)


class SignupView(CreateAPIView):
    """
    API view to handle user registration (sign-up) requests.

    This view inherits from `CreateAPIView` and provides the functionality to create a new user account 
    by accepting user details such as email, password, and any additional fields required for registration.

    Methods:
        post(request, *args, **kwargs):
            Handles the POST request to register a new user.
            Args:
                request (HttpRequest): The incoming request containing user registration data.
                *args: Additional positional arguments.
                **kwargs: Additional keyword arguments.
            Returns:
                Response: A response indicating the success or failure of the user registration.
    """
    serializer_class = SignupSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="User Signup",
        operation_description="""
            This API allows new users to register an account.
            Request Body:
            - `email` (string, required): The user's email address.
            - `password` (string, required): The desired password for the new account.
            
            The API validates that the `email` is unique. The password must meet complexity requirements.
            """,
        operation_id='signUp',
        tags=["user"],
    )

    def post(self, request, *args, **kwargs):
        """
        Handles the user registration process and sends a verification email.

        This method performs the following steps:
        1. Validates the incoming user registration data using the serializer.
        2. Checks if a user with the provided email already exists.
        3. If an existing user is found and their email is not verified:
            - If the activation token has not expired, returns an error indicating the email has already been sent.
            - If the token has expired, deletes the existing user record and allows a new registration.
        4. Creates a new user, generates an activation token, and sends a verification email.
        5. Handles database integrity errors (e.g., duplicate email) and other exceptions.

        Args:
            request (HttpRequest): The incoming request containing user registration data.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: 
                - SuccessResponse: On successful user creation and email sending with HTTP 201 status code.
                - ErrorResponse: If a user with the email already exists or other errors occur.
                - Response: If a verification email has already been sent recently.
        """

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get("email")
        existing_user = User.objects.filter(email=email).first()
        if existing_user:
            expiration_time = timezone.now() - timedelta(hours=ACTIVATION_TOKEN_EXPIRY_HOURS)
            if not existing_user.is_email_verified:
                if existing_user.activation_token_created_on >= expiration_time:
                    return Response(
                        {"status": "error", "message": "A verification email has already been sent. Please check your inbox."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                else:
                    existing_user.delete()
        try:

            with transaction.atomic():
                user = serializer.save()
                token_generator = PasswordResetTokenGenerator()
                token = token_generator.make_token(user)
                user.activation_token = token
                user.activation_token_created_on = datetime.now()
                user.save()
                # Send email verification
                send_verification_email(user, token)

            return SuccessResponse(message="A verification email has been sent to your email address", data=serializer.data, status_code=status.HTTP_201_CREATED)
        except IntegrityError as e:
            if 'unique constraint' in str(e).lower():
                return ErrorResponse(message="Email already exists")
            return ErrorResponse(message="An error occurred while processing your request")
        except Exception as e:
            return ErrorResponse(message="An unexpected error occurred", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ResendVerificationEmail(GenericAPIView):
    """
    API view to handle resend of verification mail for user signup.
    During signup, if token expired for mail verification, user can send verification mail again.

    Methods:
        post(request): Handle POST request to resend verification mail.
    """
    serializer_class = EmailSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Resend Verification Email",
        operation_description="""
            This API allows a user to resend verification email.
        """,
        operation_id='resendVerificationEmail',
        tags=["user"],
    )
    def post(self, request):
        """
        Handles the process of resending a verification email to the user.

        This method performs the following steps:
        1. Retrieves the email from the request data.
        2. Checks if a user with the provided email exists and meets the following conditions:
            - The email is not yet verified (`is_email_verified=False`).
            - The user is not blocked (`is_blocked=False`).
            - The user is not marked as deleted (`deleted_at__isnull=True`).
        3. If the user exists and was created within the last 24 hours:
            - Generates a new email verification token.
            - Updates the user's activation token and creation time.
            - Sends the verification email to the user's email address.
        4. Handles any unexpected errors and returns appropriate error responses.

        Args:
            request (HttpRequest): The incoming request containing the user's email.

        Returns:
            Response:
                - SuccessResponse: If the verification email is successfully resent with an HTTP 201 status code.
                - ErrorResponse: If an unexpected error occurs, with an HTTP 500 status code.
        """
        
        try:
            email = request.data.get('email')
            obj_user = User.objects.filter(email=email, is_email_verified=False, is_blocked=False, deleted_at__isnull=True)
            if obj_user.exists():
                user = obj_user.first()
                # Check if user is created in last 24 hours
                if (timezone.now() - user.created_at) <= timedelta(hours=24):
                    token_generator = PasswordResetTokenGenerator()
                    token = token_generator.make_token(user)
                    user.activation_token = token
                    user.activation_token_created_on = datetime.now()
                    user.save()
                    # Send email verification
                    send_verification_email(user, token)
            return SuccessResponse(message="A verification email has been resend to your email address", data=[], status_code=status.HTTP_201_CREATED)
        except Exception as e:
            print(str(e))
            return ErrorResponse(message="An unexpected error occurred", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SetPasswordView(GenericAPIView):
    """
    API view to handle resend of verification mail for user signup.
    During signup, if token expired for mail verification, user can send verification mail again.

    Methods:
        post(request): Handle POST request to resend verification mail.
    """
    serializer_class = SetPasswordSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Set Password",
        operation_description="""
            This API allows a user to set or update their password.
        """,
        operation_id='setPassword',
        tags=["user"],
    )
    def post(self, request, *args, **kwargs):
        """
        Handles setting or updating the password for a user based on a valid activation token.

        This method performs the following steps:
        1. Validates the incoming request data using the `SetPasswordSerializer`.
        2. Retrieves the activation token, new password, success URL, cancel URL, 
        and subscription plan price ID from the validated data.
        3. Checks if the activation token is valid and has not expired.
        4. If a valid user is found:
            - Sets the new password for the user.
            - Marks the user as active and verifies their email.
            - Clears the activation token and its creation timestamp.
            - Creates a checkout session for the subscription plan.
        5. Returns a success response with the checkout session data.

        Args:
            request (HttpRequest): The incoming request containing the activation token, new password, 
                                and other optional parameters.

        Returns:
            Response:
                - SuccessResponse: If the password is successfully set, with the checkout session data.
                - ErrorResponse: If the activation token is invalid or expired.

        Raises:
            serializers.ValidationError: If the input data is invalid.
            ObjectDoesNotExist: If no user is found with the provided activation token.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data.get('token')
        password = serializer.validated_data.get('password')
        success_url = serializer.validated_data.get('success_url')
        cancel_url = serializer.validated_data.get('cancel_url')
        subscription_plan_price_id = serializer.validated_data.get(
            'subscription_plan_price_id')
        expiration_time = timezone.now() - timedelta(hours=ACTIVATION_TOKEN_EXPIRY_HOURS)

        try:
            user = User.objects.get(
                activation_token=token,
                activation_token_created_on__gte=expiration_time
            )
            user.set_password(password)
            user.is_active = True
            user.is_email_verified = True
            user.activation_token = None
            user.activation_token_created_on = None
            user.save()
            data = create_checkout_session(
                user, success_url, cancel_url, subscription_plan_price_id)
        except ObjectDoesNotExist:
            return ErrorResponse(message="Invalid or expired token")

        return SuccessResponse(message="Password successfully Created", data=data)
    
class ValidateActivationToken(GenericAPIView):
    """
    API view to validate activation token.
    During email verification, token is checked for expiry date. If expired user is removed.

    Methods:
        post(request): Handle POST request to validate activation token.
    """
    serializer_class = ValidateActivationTokenSerializer
    permission_classes = [AllowAny]


    @swagger_auto_schema(
        operation_summary="Validate Token",
        operation_description="""
            This API validates the provided token to ensure it is still active and not expired.
        """,
        operation_id='validateToken',
        tags=["user"],
    )

    def post(self, request):
        """
        Validates the provided activation token to ensure it is valid and not expired.

        This method performs the following steps:
        1. Validates the incoming request data using the `ValidateActivationTokenSerializer`.
        2. Retrieves the activation token from the validated data.
        3. Checks if a user exists with the provided activation token.
        4. Verifies whether the activation token is still valid based on its expiration time.
            - If expired, the user record associated with the token is deleted.
            - If valid, returns a success response indicating the token is active.

        Args:
            request (HttpRequest): The incoming request containing the activation token.

        Returns:
            Response:
                - SuccessResponse: If the token is valid.
                - ErrorResponse: If the token is invalid, expired, or if an unexpected error occurs.

        Raises:
            serializers.ValidationError: If the input data is invalid.
            Exception: If any unexpected error occurs during token validation.
        """
        try:
            
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            token = serializer.validated_data.get('token')
            expiration_time = timezone.now() - timedelta(hours=ACTIVATION_TOKEN_EXPIRY_HOURS)

            # Fetch user associated with the token
            user = User.objects.filter(activation_token=token).first()
            if not user:
                return ErrorResponse(message="Invalid or expired token")

            # Check token expiration
            if user.activation_token_created_on < expiration_time:
                user.delete()
                return ErrorResponse(message="Invalid or expired token")

            # Token is valid
            return SuccessResponse(message="Token validation successful")

        except Exception as e:
            return ErrorResponse(message="An unexpected error occurred ", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ForgotPasswordView(GenericAPIView):
    """
    API view to send email for resetting password.
    A new token is generated for verifying password resett request, and send over email.

    Methods:
        post(request): Handle POST request to send password reset email.
    """
    permission_classes = [AllowAny]
    serializer_class = EmailSerializer


    @swagger_auto_schema(
        operation_summary="Request Password Reset Link",
        operation_description="""
            This API allows a user to request a password reset link. 
            The user must provide their registered email address. 
            If the email is associated with an account, a password reset link will be sent to that address.
        """,
        operation_id='requestPasswordResetLink',
        tags=["user"]
    )
    def post(self, request):
        """
        Sends a password reset link to the user’s email address if it is associated with a verified account.

        This method performs the following steps:
        1. Validates the email provided by the user in the request data using the `EmailSerializer`.
        2. Checks if the email is registered with a verified, active, and non-blocked user account.
        3. If a valid user is found, generates a password reset token and creates a record in the `PasswordReset` model.
        4. Sends a password reset email to the user with the reset token.

        Args:
            request (HttpRequest): The incoming request containing the user's email address.

        Returns:
            Response:
                - SuccessResponse: If the email address is associated with an account and a reset link is sent.
                - ErrorResponse: If an unexpected error occurs during the process.

        Raises:
            serializers.ValidationError: If the email data is invalid.
            Exception: If any unexpected error occurs while processing the request.
        """
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            email = serializer.validated_data['email']
            user = User.objects.filter(email__iexact=email, is_email_verified=True, is_blocked=False, deleted_at__isnull=True).first()

            if user:
                token_generator = PasswordResetTokenGenerator()
                token = token_generator.make_token(user)
                reset = PasswordReset(user=user, token=token)
                reset.save()
                send_password_reset_email(user, token)
            return SuccessResponse(message='If the email address is associated with an account, you will receive a password reset link')
        except Exception as e:
            return ErrorResponse(message="An unexpected error occurred ", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserPasswordResetView(GenericAPIView):
    """
    API view to resett user password.
    Verification token from email is validated and, if success password is changed.

    Methods:
        post(request): Handle POST request to reset password.
    """
    serializer_class = ResetPasswordSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Reset Password",
        operation_description="""
            This API allows a user to reset their password using the reset link received via email. 
            The user must provide the new password and the token received in the reset link. 
            If the token is valid and not expired, the user's password will be updated.
            """,
        operation_id='resetPassword',
        tags=["user"]
    )
    def post(self, request):
        """
        Resets the user's password based on the provided token and new password.

        This method performs the following steps:
        1. Validates the request data using the `serializer_class`.
        2. Retrieves the password reset object using the provided token.
        3. Verifies the token and finds the associated user.
        4. If a valid user is found, sets the new password and saves the user.
        5. Deletes the password reset token after the password is updated.

        Args:
            request (HttpRequest): The incoming request containing the token and new password.

        Returns:
            Response:
                - SuccessResponse: If the password is successfully updated.
                - ErrorResponse: If the token is invalid or the user is not found.

        Raises:
            serializers.ValidationError: If the request data is invalid.
            Exception: If an unexpected error occurs while processing the request.
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        new_password = data['new_password']
        token = data['token']

        reset_obj = PasswordReset.objects.filter(token=token).first()

        if not reset_obj:
            return ErrorResponse(message="Invalid token")

        user = User.objects.filter(id=reset_obj.user.id).first()

        if user:
            user.set_password(request.data['new_password'])
            user.save()

            reset_obj.delete()

            return SuccessResponse(message='Password updated')
        else:
            return ErrorResponse(message="User not found", status_code=status.HTTP_404_NOT_FOUND)


class UserChangePasswordView(GenericAPIView):
    """
        View to handle the user password change request.

        This API allows an authenticated user to change their password. 

        Methods:
        post(request): Allows the user  to change password.
    """
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Change Password",
        operation_description="""
            This API allows a logged-in user to change their password from their profile. 
            The user must provide the new password they wish to set. 
            If the password meets security requirements, the password will be updated.
        """,
        operation_id='changePassword',
        tags=["user"]
    )
    def post(self, request):
        """
        Allows the user  to change password.

        Args:
            request (HttpRequest): The HTTP request object containing new password.

        Returns:
            SuccessResponse: A JSON response with the `password updated` message.
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user

        if user:
            user.set_password(request.data['new_password'])
            user.save()

            return SuccessResponse(message='Password updated')
        else:
            return ErrorResponse(message="User not found", status_code=status.HTTP_404_NOT_FOUND)


def send_password_reset_email(user, token):
    """
        Sends a password reset email to the user with a reset link containing the token.

        This function generates a password reset email for a user. The email includes a link 
        to the password reset page with the token as a query parameter, allowing the user 
        to securely reset their password.

        Args:
            user (User): The user object to whom the password reset email is to be sent.
            token (str): The password reset token to be included in the email link.

        Returns:
            None

        Raises:
            Exception: If there is an error in sending the email.
    """
    subject = "Beek Health - Reset your password"
    template = "password_reset_template.html"  # Assuming you have a template
    context = {
        'name': f"{user.name}",
        'link': f"{PASSWORD_RESET_FE_URL}?token={token}",
        'fe_url': f"{config('FE_URL')}"
    }
    to_email = user.email

    return send_custom_email(subject, template, context, to_email)


def send_verification_email(user, token):
    """
        Sends a verification email to the user with a token to confirm their email address.

        This function generates a verification email for the user, including a unique 
        token that they can use to activate their account. The email contains a link 
        with the token embedded, allowing the user to verify their email address.

        Args:
            user (User): The user object representing the account to verify.
            token (str): The token used to verify the user's email address.

        Returns:
            None

        Raises:
            Exception: If there is an error while sending the email.
    """
    subject = "Beek Health - Complete Your Account Creation"
    template = "email_verification_template.html"

    context = {
        'name': f"{user.name}",
        'link': f"{EMAIL_VERIFICATION_FE_URL}?token={token}",
        'fe_url': f"{config('FE_URL')}"
    }
    to_email = user.email

    return send_custom_email(subject, template, context, to_email)


class UserProfileView(GenericAPIView):
    """
        API view to retrieve and update the user profile.

        This view allows the user to retrieve their profile information or update
        certain fields of their profile, such as name, email, or password. It is
        intended to be used by authenticated users to manage their own profile details.

        Methods:
            get: Retrieves the current profile details of the authenticated user.
            patch: Updates the profile details of the authenticated user.
    """
    queryset = PersonalInfo.objects.all()
    serializer_class = PersonalInfoSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="User Profile View",
        operation_description="""
            This API retrieves the profile information of the currently logged-in user. 
        """,
        operation_id='viewUserProfile',
        tags=["user"]
    )
    def get(self, request):
        """
            Retrieves the personal information of the authenticated user.

            This method checks if the authenticated user already has personal information.
            If available, it retrieves and returns the existing data. If no personal information
            is found, it creates a new record and returns the newly created data.

            Args:
                request: The HTTP request object containing the authenticated user's information.

            Returns:
                SuccessResponse: A response containing the user's personal information (either 
                                retrieved or newly created) serialized into the appropriate format.
        """
        personal_info_queryset = self.request.user.personal_info.all()
        if personal_info_queryset.exists():
            data = personal_info_queryset.first()
            serialized_data = self.serializer_class(data).data
        else:
            user = User.objects.get(pk=self.request.user.pk)
            personal_info = PersonalInfo.objects.create(user=user)
            serialized_data = self.serializer_class(personal_info).data
        return SuccessResponse(data=serialized_data)

    def get_object(self):
        return self.queryset.get(user=self.request.user)

    @swagger_auto_schema(
        operation_summary="User Profile Edit",
        operation_description="""
            This API edits the profile information of the currently logged-in user. 
        """,
        operation_id='editUserProfile',
        tags=["user"]
    )
    def patch(self, request, *args, **kwargs):
        """
            Partially updates the personal information of the authenticated user.

            This method allows the user to update specific fields such as their name and email notification preferences.
            It first checks if the user has existing personal information. Then, it updates the `User` model and 
            the `PersonalInfo` model as necessary based on the data provided in the request.

            Args:
                request: The HTTP request object containing the fields to update and the authenticated user's information.
                *args: Additional positional arguments.
                **kwargs: Additional keyword arguments.

            Returns:
                SuccessResponse: A response containing the updated user profile data if successful.
                ErrorResponse: A response containing validation errors if the update is unsuccessful.
        """
        user_profile = self.request.user.personal_info.first()
        user = User.objects.filter(pk=self.request.user.id)
        if 'name' in request.data:
            user.update(name=request.data.get('name'))
        if 'is_email_notifications_enabled' in request.data:
            user.update(is_email_notifications_enabled=request.data.get(
                'is_email_notifications_enabled'))
        serializer = self.serializer_class(
            user_profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return SuccessResponse(data=serializer.data, status=status.HTTP_200_OK)
        else:
            return ErrorResponse(errors=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeleteAccountView(APIView):
    """
        Handles the deletion of the authenticated user's account.

        This view allows an authenticated user to delete their account from the system. 
        Upon successful deletion, the user will be logged out.

        The user will be required to confirm their email id to delete the account, and 
        once the action is completed, a success message will be returned.

        Permissions:
            - Only authenticated users are allowed to access this view.

        Methods:
            - DELETE: Initiates the account deletion process and removes the user's data.
            - mask_email: User email is encrypted using SHA256.
            - mask_phone: User phone number is masked using SHA256.
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Delete Account",
        operation_description="""
            This API allows a logged-in user to delete their account permanently. 
            The user must confirm their decision to ensure that the account deletion is intentional.
        """,
        operation_id='deleteAccount',
        tags=["user"]
    )
    def delete(self, request):
        """
            Handle account deletion for the authenticated user.

            This method marks the user as deleted by updating relevant fields such as:
            - Setting the `deleted_at` timestamp to indicate the deletion time.
            - Masking the user's personal information (name, email, phone number).
            - Cancelling any active subscriptions via the Stripe API.
            
            Additionally, the user’s subscription status is updated, and the associated 
            payment method is marked as deleted.

            The user will not be permanently deleted from the database but will be flagged 
            as deleted.

            Steps:
                1. Marks the user's account as deleted by updating fields like `name`, 
                `phone_number`, and `email`.
                2. Cancels the user's active subscription with Stripe by setting 
                `cancel_at_period_end` to `True`.
                3. Updates the user's subscription status and flags the payment method 
                as deleted.
                
            Returns:
                SuccessResponse: A message indicating the successful deletion of the account.
        """
        user = request.user
        # user.is_active = False
        user.deleted_at = datetime.now()
        # Update the email with the timestamp
        user.name = 'Deleted User'
        user.phone_number = self.mask_phone(user.phone_number)
        user.email = self.mask_email(user.email)
        user.save()
        try:
            user_subscriptions_obj = UserSubscriptions.objects.filter(
                user_id=user.id, is_active=True, is_expired=False).order_by("-created_at").first()
            stripe.Subscription.modify(
                user_subscriptions_obj.stripe_id,
                cancel_at_period_end=True
            )
            # user_subscriptions_obj.is_active = False # not needed, handled via Webhook
            user_subscriptions_obj.payment_method_deleted = True
            user_subscriptions_obj.cancelled_on = datetime.now(timezone.utc)
            # user_subscriptions_obj.status = 'cancelled' # not needed, handled via Webhook
            user_subscriptions_obj.save()
        except Exception as e:
            print(e)
        return SuccessResponse(message="Account deleted successfully.", status_code=status.HTTP_205_RESET_CONTENT)

    def mask_email(self, email):
        """
            Mask an email address by hashing the username portion with SHA-256 
            and replacing the domain with the last 10 characters of the hash.

            Args:
                email (str): The email address to be masked.

            Returns:
                str: The masked email address in the format `<hashed_username>@<last_10_characters_of_hash>.com`.
        """
        masked_username = hashlib.sha256(email.encode()).hexdigest()
        masked_username = masked_username[:-10] + '@' + masked_username[-10:]
        masked_email = f'{masked_username}.com'
        return masked_email

    def mask_phone(self, phone_number):
        """
            Mask a phone number by hashing it with SHA-256 and returning the first 18 characters of the hash.

            Args:
                phone_number (str): The phone number to be masked.

            Returns:
                str: The masked phone number consisting of the first 18 characters of the SHA-256 hash.

        """
        masked_phone_number = hashlib.sha256(phone_number.encode()).hexdigest()
        return masked_phone_number[:18]


class CreateSubscription(GenericAPIView):
    """
    This API endpoint creates a new subscription for a user using Stripe.

    Methods:
        post(request):
            Creates a new subscription for the authenticated user based on the provided subscription plan.

    Attributes:
        serializer_class: The serializer used to validate the incoming request data.
        permission_classes: List of permission classes that define access control for this view.
    Returns : data
    """
    serializer_class = CreateSubscriptionSerializer
    permission_classes = [IsAuthenticated]
    stripe.api_key = config('STRIPE_SECRET')


    @swagger_auto_schema(
    operation_summary="Create Subscription",
    operation_description="""
        This API allows a user to create a new subscription. 
        The user must provide the necessary details such as subscription type.
    """,
    operation_id='createSubscription',
    tags=["user"],
    request_body=CreateSubscriptionSerializer,
    )
    def post(self, request):
        """
            Handle the creation of a Stripe checkout session for a subscription.

            This method creates a new Stripe checkout session for the authenticated user based on the 
            provided subscription plan and redirects to either a success or cancel URL upon completion.

            Parameters:
                request (Request): The HTTP request object containing the following data:
                    - success_url (str): The URL to redirect to upon successful subscription creation.
                    - cancel_url (str): The URL to redirect to if the subscription creation is canceled.
                    - subscription_plan_price_id (str): The Stripe price ID of the subscription plan.

            Returns:
                Response: A JSON response with the following structure:
                    - message (str): A message indicating the result of the operation.
                    - data (dict or list): On success, contains the Stripe checkout session data. 
                    On failure, returns an empty list.
            Raises:
                Exception: Captures and logs any exception that occurs during the process and returns
                a 400 BAD REQUEST response if the checkout session creation fails.
        """
        success_url = request.data.get('success_url')
        cancel_url = request.data.get('cancel_url')
        subscription_plan_price_id = request.data.get(
            'subscription_plan_price_id')
        try:
            stripe_data = create_checkout_session(
                self.request.user, success_url, cancel_url, subscription_plan_price_id)
            return Response({"message": "Checkout created successfully", "data": stripe_data}, status=status.HTTP_200_OK)
        except Exception as e:
            print(e)
            return Response({"message": bad_request_err_msg, "data": []}, status=status.HTTP_400_BAD_REQUEST)


class StripeWebhooks(APIView):
    """
        A view to handle incoming Stripe webhook events.

        This view listens for webhook events from Stripe, processes them, and updates the application's
        data accordingly. It can handle events like payment success, payment failure, subscription updates,
        and others by receiving data sent by Stripe's servers.

        It supports the following events (example):
            - `payment_intent.succeeded`: Triggered when a payment is successfully completed.
            - `payment_intent.payment_failed`: Triggered when a payment fails.
            - `customer.subscription.created`: Triggered when a new subscription is created.
            - `customer.subscription.updated`: Triggered when a subscription is updated.
            - `customer.subscription.deleted`: Triggered when a subscription is canceled or deleted.
            - `checkout.session.completed` : Triggered when a checkout session is completed.
            - `checkout.session.expired` : Triggered when a checkout session is expired.
            - `invoice.paid` : Triggered when a invoice is paid.
            - `invoice.upcoming` : Triggered when a invoice is upcoming.

        Methods:
            post: Receives and processes the incoming webhook event from Stripe.
            handle_checkout_session_completed: checkout.session.completed is captured and logged in database.
            handle_checkout_session_expired: Handles the 'checkout.session.expired' event from Stripe.
            handle_subscription_created: When customer is created in stripe, details are updated in db.
            handle_subscription_updated: When subscription is updated in stripe, new billing period is added in db.
            handle_invoice_paid: When invoice payment is suuccesful, user subscription is marked active.
            handle_payment_failed: If stripe invoice payment is failed, user subscription is marked inactive.
            handle_subscription_deleted: When subscription is dleted by user, status is changed to inactive.
            logEvents: Logs captured stripe events in database.
            
        Attributes:
            stripe_endpoint_secret (str): The secret used to validate the incoming webhook request from Stripe.
            stripe_event_types (list): A list of Stripe event types that this handler processes.
    """
    permission_classes = []
    authentication_classes = []

    @swagger_auto_schema(auto_schema=None)
    @method_decorator(csrf_exempt)
    def post(self, request):
        payload = request.body
        sig_header = request.headers.get('STRIPE_SIGNATURE')
        endpoint_secret = config('STRIPE_WEBHOOK')

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, endpoint_secret)
        except (ValueError, stripe.error.SignatureVerificationError) as e:
            error_type = 'value error' if isinstance(
                e, ValueError) else 'signature verification error'
            self.logEvents(f'Error - {error_type}', str(e), None)
            return JsonResponse({"success": False, "message": f'Error - {error_type}'}, status=400 if isinstance(e, ValueError) else 401)

        try:
            event_type = event['type']
            stripe_obj = event['data']['object']

            if event_type == 'checkout.session.completed':
                self.handle_checkout_session_completed(stripe_obj)
            elif event_type == 'checkout.session.expired':
                self.handle_checkout_session_expired(stripe_obj)
            elif event_type == 'customer.subscription.created':
                self.handle_subscription_created(stripe_obj)
            elif event_type == 'customer.subscription.updated':
                self.handle_subscription_updated(stripe_obj)
            elif event_type == 'invoice.paid':
                self.handle_invoice_paid(stripe_obj)
            elif event_type == 'payment_intent.payment_failed':
                self.handle_payment_failed(stripe_obj)
            elif event_type == 'invoice.upcoming':
                self.logEvents(
                    stripe_obj['subscription'], event_type, stripe_obj)
            elif event_type == 'customer.subscription.deleted':
                self.handle_subscription_deleted(stripe_obj)
            else:
                self.logEvents(stripe_obj['id'], event_type, stripe_obj)

            return JsonResponse({"success": True}, status=200)
        except Exception as e:
            self.logEvents(f'Error {event_type}', str(e), None)
            return JsonResponse({"success": True}, status=202)

    def handle_checkout_session_completed(self, stripe_obj):
        """
            Handles the 'checkout.session.completed' event from Stripe.

            This method processes the checkout session completion event sent by Stripe. It is typically triggered
            when a customer successfully completes the payment during the checkout process. Upon receiving this event,
            the method performs necessary actions such as updating the user's subscription status, saving payment information,
            and logging relevant details to ensure the backend data is consistent with Stripe.

            Args:
                stripe_obj (dict): The event data from Stripe's webhook, containing details about the checkout session
                                and the associated payment.

            Returns:
                None: This method performs actions but does not return a value.
        """
        self.logEvents(stripe_obj['id'],
                       'checkout.session.completed', stripe_obj)

    def handle_checkout_session_expired(self, stripe_obj):
        """
            Handles the 'checkout.session.expired' event from Stripe.

            This method processes the event triggered when a checkout session has expired in Stripe. 
            Upon receiving this event, it cleans up any incomplete subscription or payment-related data 
            in the backend system.

            Args:
                stripe_obj (dict): The event data from Stripe, which contains details about the expired session, 
                                including session ID, customer information, and the products involved.

            Returns:
                None: This method performs cleanup actions but does not return a value.
        """
        self.logEvents(stripe_obj['id'],
                       'checkout.session.expired', stripe_obj)

    def handle_subscription_created(self, stripe_obj):
        """
            Handles the 'customer.subscription.created' event from Stripe.

            This method processes the event triggered when a new subscription is created for a customer in Stripe. 
            Upon receiving this event, it updates the backend system to reflect the newly created subscription,
            including saving relevant subscription details to the database and ensuring the user’s subscription status is updated.

            Args:
                stripe_obj (dict): The event data from Stripe, which contains details about the subscription,
                                including the customer, plan, and subscription ID.

            Returns:
                None: This method performs actions but does not return a value.
        """
        user_stripe_id = stripe_obj.get('customer')
        if user_stripe_id:
            user = User.objects.filter(stripe_id=user_stripe_id, deleted_at__isnull=True).first()
            user_subscriptions_obj = UserSubscriptions()
            user_subscriptions_obj.user_id = user.id
            user_subscriptions_obj.stripe_id = stripe_obj['id']
            user_subscriptions_obj.subscription_plan_id = MasterSubscriptionPlanPrice.objects.filter(
                stripe_id=stripe_obj['plan']['id']).first().id
            user_subscriptions_obj.stripe_status = 'active'
            # user_subscriptions_obj.status = 'active' # no need, default set to trial
            user_subscriptions_obj.is_active = True
            user_subscriptions_obj.save()
            create_1UP_user(user)
        self.logEvents(stripe_obj['id'],
                       'customer.subscription.created', stripe_obj)

    def handle_subscription_updated(self, stripe_obj):
        """
            Handles the 'customer.subscription.updated' event from Stripe.

            This method processes the event triggered when a customer's subscription is updated in Stripe.
            It handles updates such as changes in subscription plans, status changes (e.g., from active to past_due),
            or changes to the payment method. This ensures that the subscription status is accurately reflected in 
            the backend system.

            Args:
                stripe_obj (dict): The event data from Stripe, which contains details about the updated subscription,
                                including the subscription ID, customer information, new subscription plan, 
                                and any changes in status or payment details.

            Returns:
                None: This method updates the subscription status and associated data in the backend but does not return a value.
        """
        subscription_id = stripe_obj['id']
        customer_stripe_id = stripe_obj['customer']
        user = User.objects.filter(stripe_id=customer_stripe_id, deleted_at__isnull=True).first()
        if subscription_id:
            billing_period_start = datetime.fromtimestamp(
                stripe_obj['current_period_start'], pytz.UTC)
            billing_period_end = datetime.fromtimestamp(
                stripe_obj['current_period_end'], pytz.UTC)

            user_subscription = UserSubscriptions.objects.filter(
                user=user, stripe_id=subscription_id, is_deleted=False).order_by("-created_at").first()
            if user_subscription and stripe_obj['cancel_at_period_end']:
                user_subscription.billing_period_start = billing_period_start
                user_subscription.billing_period_end = billing_period_end
                user_subscription.stripe_status = 'inactive'
                user_subscription.is_active = False
                user_subscription.save()

        self.logEvents(stripe_obj['id'],
                       'customer.subscription.updated', stripe_obj)

    def handle_invoice_paid(self, stripe_obj):
        """
            Handles the 'invoice.paid' event from Stripe.

            This method processes the event triggered when an invoice payment is successfully processed and paid.
            It is typically used to update the backend system with payment status, confirm the subscription's active state.
            Args:
                stripe_obj (dict): The event data from Stripe, which contains details about the paid invoice, 
                                including the invoice ID, customer details, payment method, and the associated subscription.

            Returns:
                None: This method updates the backend system, such as marking the subscription as active or paid,
                    but does not return a value.
        """
        subscription_id = stripe_obj['subscription']
        customer_stripe_id = stripe_obj['customer']
        user = User.objects.filter(stripe_id=customer_stripe_id, deleted_at__isnull=True).first()
        if user:
            invoice_details = stripe.Invoice.retrieve(
                stripe_obj['id'], expand=['payment_intent', 'subscription'])
            subscription_obj = stripe.Subscription.retrieve(subscription_id)

            billing_period_start = datetime.fromtimestamp(
                subscription_obj['current_period_start'], pytz.UTC)
            billing_period_end = datetime.fromtimestamp(
                subscription_obj['current_period_end'], pytz.UTC)

            user_subscription = UserSubscriptions.objects.filter(
                user=user, stripe_id=subscription_id).order_by("-created_at").first()
            if user_subscription:
                user_subscription.billing_period_start = billing_period_start
                user_subscription.billing_period_end = billing_period_end
                user_subscription.stripe_status = 'active'
                if int(stripe_obj['amount_paid']) and int(stripe_obj['amount_due']):
                    user_subscription.status = 'active'
                user_subscription.is_active = True
                user_subscription.is_deleted = False
                user_subscription.is_expired = False
                user_subscription.cancelled_on = None
                user_subscription.save()

        self.logEvents(stripe_obj['id'], 'invoice.paid', stripe_obj)

    def handle_payment_failed(self, stripe_obj):
        """
            Handles the 'invoice.payment_failed' event from Stripe.

            This method processes the event triggered when a payment attempt for an invoice fails. 
            It is typically used to update the backend system with payment failure details
            and take appropriate actions, such as deactivating the subscription.

            Args:
                stripe_obj (dict): The event data from Stripe, which contains details about the failed payment,
                                including the invoice ID, customer information, the reason for the payment failure, 
                                and the associated subscription.

            Returns:
                None: This method updates the backend system, such as marking the subscription as failed or updating the payment status, 
                    but does not return a value.
        """
        subscription_obj = stripe.Subscription.list(
            customer=stripe_obj['customer'])
        subscription_id = subscription_obj['data'][0]['id']
        user = User.objects.filter(stripe_id=stripe_obj['customer'], deleted_at__isnull=True).first()

        user_subscription = UserSubscriptions.objects.filter(
            user=user, stripe_id=subscription_id, is_deleted=False).order_by("-created_at").first()
        if user_subscription:
            user_subscription.stripe_status = 'inactive'
            user_subscription.is_active = False
            user_subscription.is_deleted = True
            user_subscription.is_expired = True
            user_subscription.cancelled_on = datetime.now(timezone.utc)
            user_subscription.status = 'cancelled'
            user_subscription.save()

        self.logEvents(stripe_obj['id'],
                       'payment_intent.payment_failed', stripe_obj)

    def handle_subscription_deleted(self, stripe_obj):
        """
            Handles the 'customer.subscription.deleted' event from Stripe.

            This method processes the event triggered when a subscription is canceled or deleted on Stripe. 
            It is typically used to update the backend system to reflect the subscription status, 
            deactivate user access and canceling active subscriptions in the database.

            Args:
                stripe_obj (dict): The event data from Stripe, which contains details about the deleted subscription,
                                including the subscription ID, customer details, cancellation reason, and any associated payment information.

            Returns:
                None: This method updates the backend system (e.g., marks the subscription as canceled, deactivates user access),
                    but does not return a value.
        """
        payment_method_id = stripe_obj['default_payment_method']
        subscription_id = stripe_obj['id']

        user_subscription = UserSubscriptions.objects.filter(
            stripe_id=subscription_id).order_by("-created_at").first()
        if user_subscription:
            user_subscription.is_active = False
            user_subscription.is_deleted = True
            user_subscription.is_expired = True
            user_subscription.payment_method_deleted = True
            user_subscription.stripe_status = 'inactive'
            user_subscription.status = 'expired'
            user_subscription.save()

        stripe.PaymentMethod.detach(payment_method_id)
        self.logEvents(stripe_obj['id'],
                       'customer.subscription.deleted', stripe_obj)

    def logEvents(self, stripe_id, event_type, data):
        """
            Logs events related to Stripe transactions.

            This method stores information about Stripe events (such as subscription updates, payments, or cancellations) 
            in the backend system for tracking and auditing purposes. The log entry includes the Stripe ID, event type, 
            and relevant event data.

            Args:
                stripe_id (str): The unique identifier of the Stripe object (e.g., subscription ID, payment ID) associated with the event.
                event_type (str): A string describing the type of event (e.g., 'subscription.created', 'invoice.paid').
                data (dict): A dictionary containing detailed information about the event, such as customer details, subscription status,
                            payment amounts, and other relevant data specific to the event.

            Returns:
                None: This method does not return any values but creates a log entry for auditing purposes.
        """
        try:
            LogStripeWebhook.objects.create(
                stripe_id=stripe_id,
                event_name=event_type,
                stripe_response=data
            )
        except Exception as e:
            print(str(e))


class CancelSubscription(APIView):
    """
        API view to cancel a user's subscription.

        This view allows authenticated users to cancel their active subscription. Upon successful cancellation, 
        the subscription's status is updated, and the associated payment method is deactivated. The cancellation 
        process include stopping recurring payments.

        Methods:
            delete: Cancels user subscriptoin from stripe.

        Permission:
            - Authenticated users can access this view and cancel their own subscription.

        Request Parameters:
            - None (The user's subscription is identified automatically via authentication).

        Returns:
            - A response indicating the success or failure of the cancellation.

        Error Responses:
            - 400 Bad Request: If the cancellation request is invalid or the subscription cannot be found.
            - 404 Not Found: If the subscription does not exist for the authenticated user.

        Notes:
            - The cancellation is applied at the end of the billing cycle.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = UserSubscriptionSerializer
    stripe.api_key = config('STRIPE_SECRET')

    @swagger_auto_schema(
        operation_summary="Cancel Subscription",
        operation_description="""
            This API allows a user to cancel their existing subscription. 
            The user must provide the subscription ID to identify which subscription to cancel
        """,
        operation_id='cancelSubscription',
        tags=["user"]
    )
    def delete(self, request):
        """
            API method to cancel a user's subscription.
            The cancellation is processed immediately, but the subscription may remain active until the end of the billing cycle.

            Permissions:
                - Authenticated users can cancel their own subscriptions.

            Request:
                - The user must be authenticated and have an active subscription.

            Response:
                - Success: A message confirming the cancellation of the subscription.
                - Failure: An error message if the subscription could not be canceled, or if the user does not have an active subscription.
        """
        user_id = request.user.id
        try:
            user_subscriptions_obj = UserSubscriptions.objects.filter(
                user_id=user_id, is_active=True, is_expired=False).order_by("-created_at").first()
            stripe.Subscription.modify(
                user_subscriptions_obj.stripe_id,
                cancel_at_period_end=True
            )
            # user_subscriptions_obj.is_active = False # not needed, handled via Webhook
            user_subscriptions_obj.payment_method_deleted = True
            user_subscriptions_obj.cancelled_on = datetime.now(timezone.utc)
            # user_subscriptions_obj.status = 'cancelled' # not needed, handled via Webhook
            user_subscriptions_obj.save()
            return Response({"message": "Subscription cancelled successfully", "data": []}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"message": bad_request_err_msg, "data": []}, status=status.HTTP_406_NOT_ACCEPTABLE)


class SubscriptionListView(ListAPIView):
    """
        API view to list subscriptions.

        This view returns a list of subscriptions for the authenticated user, displaying details such as 
        subscription status, plan.

        Methods:
            get: Handles GET request for serialized list of subscription options.

        Permission:
            - Authenticated as well as non authenticated users can access this view.
        Returns:
            A list of subscription objects for the authenticated user.
    """
    queryset = MasterSubscriptionPlanPrice.objects.filter(is_active=True)
    serializer_class = SubscriptionSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="List Subscriptions",
        operation_description="Retrieve a list of active subscription plans",
        operation_id='listSubscriptions',
        tags=['subscription'],
        responses={200: SubscriptionSerializer(many=True)},  # Expected response
    )
    def get(self, request, *args, **kwargs):
        """Customized swagger schema for GET"""
        return super().get(request, *args, **kwargs)
