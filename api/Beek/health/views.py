
from beek.responses import SuccessResponse, ErrorResponse
from rest_framework import status
from rest_framework.views import APIView, View
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import OrderingFilter
from .models import (Provider, UserServiceToken, Prescription, ServiceProvider, Service, Allergy, Immunization, Document,
                     Encounter, Condition)
from user.models import PersonalInfo, User, ALLOWED_EXCERCISE_CHOICES
from .serializers import (ProvidersListSerializer, PrescriptionSerializer, GeneralHealthSerializer,
                           AllergySerializer, ImmunizationSerializer, ProfileAdditionalInfoSerializer,
                           DocumentSerializer, ConnectedProvidersSerializer, EncounterSerializer, ConditionSerializer)
from decouple import config
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.shortcuts import redirect
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
import requests
from rest_framework import viewsets
from datetime import datetime
from user.models import ALLOWED_EXCERCISE_CHOICES, ALLOWED_GOALS_CHOICES
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.generics import GenericAPIView, ListAPIView
from rest_framework.parsers import MultiPartParser, FormParser
from .utils import delete_file_from_s3, sanitize_pdf
from rest_framework.permissions import IsAuthenticated
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
import boto3
from django.conf import settings
from botocore.config import Config
from beek.permissions import HasActiveSubscription, HasActiveSubscriptionOrAdmin
from .filters import DocumentFilter, EncounterFilter
import redis
import threading
import json
from health.utils import send_task_on_provider_connect
from rest_framework.exceptions import NotFound
from beek.settings import ssl_enabled
import mimetypes



bad_request_err_msg = "Something went wrong"


def generateAccessToken(refresh_token, user, client_id, client_secret):
    """
    Generate access token for user to connect with 1UP, 
    This function generates a valid code from 1UP which is used to henerate access token
    Args: 
        user(object): user model object
        client_id(string): 1UP account client id
        client_secret(string): 1UP client secret
    Returns:
        access_token(string): user access token for accessing 1UP api's
    """
    try:
        code = getAuthorizationCode(user, client_id, client_secret)
        access_token = getAccessTokenFromCode(user, code, client_id, client_secret)
        return access_token
    except Exception as e:
        print(e)

def getAccessTokenFromCode(user, code, client_id, client_secret):
    """
    Using a valid auth code, 1UP access token is created
    Args: 
        code(string): user 1UP auth code
        client_id(string): 1UP account client id
        client_secret(string): 1UP client secret
    Returns:
        access_token(string): user access token for accessing 1UP api's
    """
    try:
        url = "https://auth.1up.health/oauth2/token"

        payload = f'client_id={client_id}&client_secret={client_secret}&code={code}&grant_type=authorization_code'
        headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = requests.request("POST", url, headers=headers, data=payload)
        data = response.json()
        access_token = data['access_token']
        user_service_token_obj = UserServiceToken.objects.get(
            user=user)
        user_service_token_obj.access_token = access_token
        user_service_token_obj.refresh_token = data['refresh_token']
        user_service_token_obj.save()
        return access_token
    except Exception as e:
        print(str(e))
        return False

def getAuthorizationCode(user, client_id, client_secret):
    """
    generate new auth code for user
    Args: 
        user(object): user model object
        client_id(string): 1UP account client id
        client_secret(string): 1UP client secret
    Returns:
        access_token(string): user access token for accessing 1UP api's
    """
    try:
        user_id = str(user.id)
        url = f"{config('1UP_BASE_URL')}user-management/v1/user/auth-code?app_user_id={user_id}&client_id={client_id}&client_secret={client_secret}"
        payload = {}
        headers = {}
        response = requests.request(
            "POST", url, headers=headers, data=payload)
        if response.status_code == 200:
            data = response.json()
            user_service_token_obj = UserServiceToken.objects.get(user=user)
            user_service_token_obj.code = data['code']
            user_service_token_obj.save()
            return data['code']
        else:
            # getAuthorizationCode(user_id, client_id, client_secret)
            print(response.json())
    except Exception as e:
        print(str(e))
        return False

class ProvidersList(ListAPIView):
    """
    Api for listing providers

    Methods:
        get(request): Handles GET requests to retrieve all providers.
        getProviderList: Retrieves providers from 1UP
        get_provider: Retrieves providers from database
        write_to_database: Store providers to database after retrieving from 1UP
    """
    serializer_class = ProvidersListSerializer
    pagination_class = None
    permission_classes = [IsAuthenticated, HasActiveSubscriptionOrAdmin]


    def __init__(self):
        self.client_id = config('1UP_CLIENT_ID')
        self.client_secret = config('1UP_CLIENT_SECRET')
        self.redis_client = redis.StrictRedis(host=config('WS_REDIS_HOST'), port=config('WS_REDIS_PORT'), db=0, \
                                              password=config('WS_REDIS_PASSWORD'), ssl=ssl_enabled, ssl_cert_reqs=None)


    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                "name",
                openapi.IN_QUERY,
                description="provider name",
                type=openapi.TYPE_STRING,
            ),
        ],
        operation_summary="List of Providers", 
        operation_description="Retrieve a list of providers.",
        operation_id="getProviders",
        tags=["health"]
    )
    def get(self, request):
        """
        Retrieves and returns a list of all providers.

        Args:
            request (Request): The HTTP request object.

        Returns:
            data: A response containing a serialized list of providers.
        """
        try:
            user = self.request.user
            if Provider.objects.exists():
                data = self.get_provider()
            else:
                user_service_token_obj = UserServiceToken.objects.filter(
                    user=user).get()
                access_token = generateAccessToken(
                    user_service_token_obj.refresh_token, user, self.client_id, self.client_secret)
                self.getProviderList(access_token, self.client_id, self.client_secret)
                data = self.get_provider()
            return SuccessResponse(message="Provider list", data=data)
        except Exception as e:
            print(e)
            return ErrorResponse(message=str(e), status_code=status.HTTP_400_BAD_REQUEST)

    def getProviderList(self, access_token, client_id, client_secret):
        """
        Retrieves a list of all providers from 1UP.

        Args:
            access_token(string): 1UP user access token
            client_id(string): 1UP account client id
            client_secret(string): 1UP client secret

        Returns:
            boolean: True if data is fetched, False if exception occured
        """
        try:
            url = f"https://api.1up.health/connect/system/clinical?client_id={client_id}&client_secret={client_secret}"
            headers = {
                'Authorization': 'Bearer '+access_token,
                'Content-Type': 'application/json'
            }
            response = requests.get(url, headers=headers)
            response_data = response.json()
            data = []
            for provider in response_data:
                provider_data = {
                    'id': '',
                    'name': provider['name'],
                    'reference': provider['id'],
                    'is_active': True,

                }
                data.append(provider_data)
            self.redis_client.set('provider_list', json.dumps(data))
            thread = threading.Thread(target=self.write_to_database, args=(response_data,))
            thread.start()
            return True
        except Exception as e:
            print(e)
            return False
    
    def get_provider(self):
        """
        Retrieves a list of all providers. 
        If data exists in redis, then list is taken from redis, else from database

        Args:
            name(string): provider name to search on list

        Returns:
            data: A response containing a serialized list of providers
        """
        try:
            obj_serviceprovider = ServiceProvider.objects.filter(user=self.request.user, deleted_at__isnull=True).values_list('provider__reference', flat=True)
            name = self.request.GET.get('name')
            try:
                redis_data = self.redis_client.get('provider_list')
                if redis_data:
                    data = json.loads(redis_data)
                    if name:

                        matching_providers = [item for item in data if name.lower() in item.get('name', '').lower()]
                        result = [item for item in matching_providers  if (str(item.get('reference')) not in list(obj_serviceprovider))]
                        return result
                    else:
                        return data
            except Exception as e:
                print(str(e))
                if name:
                    filters = {'name__contains': name, "is_active": True}
                else:
                    filters = {"is_active": True}
                provider_obj = Provider.objects.filter(**filters).exclude(reference__in=obj_serviceprovider)
                serializer = ProvidersListSerializer(provider_obj, many=True)
                matching_providers = serializer.data
                return matching_providers
        except Exception as e:
            print(str(e))
            return []
        
    def write_to_database(self, data):
        """
        Handle database writes. 

        Args:
            data(list): list of providers

        Returns:
            None
        """
        for provider in data:
            try:
                Provider.objects.get(reference=provider['id'])
            except Provider.DoesNotExist:
                provider_obj = Provider()
                provider_obj.name = provider['name']
                provider_obj.reference = provider['id']
                provider_obj.is_active = True
                provider_obj.save()

class ConnectToProvider(View):
    """
    Connect with provider for user authentication and permission for fetching user data to 1UP and database

    Methods:
        get(request): Redirects to 1UP provider login page.
    """

    def __init__(self):
        self.client_id = config('1UP_CLIENT_ID')
        self.client_secret = config('1UP_CLIENT_SECRET')

    def get(self, request):
        """
        Redirects to 1UP provider login page.

        Args:
            user_id (string): UUID of requesting user.
            provider_id (string): 1UP reference id of provider to connect.
            redirect_url (string): A URL to redirect on success.

        Returns:
            url (string): redirect url
        """
        try:
            user_id = request.GET.get('user_id')
            provider_id = request.GET.get('provider_id')
            redirect_url = request.GET.get('redirect_url')
            request.session['frontend_return_url'] = redirect_url
            user_service_token_obj = UserServiceToken.objects.filter(
                user=user_id).get()
            request.session['user_service_id'] = str(user_service_token_obj.id)
            request.session['user_id'] = str(user_id)
            request.session['provider_id'] = str(provider_id)
            user_obj = User.objects.filter(id=user_id, deleted_at__isnull=True).first()
            access_token = generateAccessToken(
                user_service_token_obj.refresh_token, user_obj, self.client_id, self.client_secret)
            url = f'https://api.1up.health/connect/system/clinical/{provider_id}?client_id={self.client_id}&access_token={access_token}'
            return redirect(url)
        except Exception as e:
            print(e)
            return ErrorResponse(message=str(e), status_code=status.HTTP_400_BAD_REQUEST)


class ConnectToProviderCallback(View):
    """
    After successful authentication and permission granting, 1UP redirects to registered redirect URL.
    This method saves connected provider and starts initial sync

    Methods:
        get(request): Initiates initial sync.
    """
    permission_classes = []
    authentication_classes = []

    def get(self, request):
        """
        Store connected provider to database and initiates initial sync.

        Args:
            user_id (string): UUID of requesting user (stored in session).
            provider_id (string): 1UP reference id of provider to connect (stored in session).
            frontend_return_url (string): A URL to redirect on success.
            user_service_id (string): user service id

        Returns:
            redirect
        """
        
        try:
            obj_user = User.objects.filter(id=request.session.get('user_id')).first()
            obj_service = Service.objects.first()
            obj_provider = Provider.objects.filter(reference=request.session.get('provider_id')).first()
            obj_serviceprovider = ServiceProvider()
            obj_serviceprovider.user = obj_user
            obj_serviceprovider.provider = obj_provider
            obj_serviceprovider.service = obj_service
            obj_serviceprovider.save()
            frontend_return_url = request.session.get('frontend_return_url')
            user_service_id = request.session.get('user_service_id')

            send_task_on_provider_connect(user_service_id, is_initial_provider_sync=True)
            
            return redirect(frontend_return_url)
        except Exception as e:
            print(str(e))

class SendMessage(APIView):
    """
    Api to send message through websocket

    Methods:
        get(request): send message through websocket.
    """
    permission_classes = []
    authentication_classes = []

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                "message",
                openapi.IN_QUERY,
                description="message content",
                type=openapi.TYPE_STRING,
            ),
            openapi.Parameter(
                "group",
                openapi.IN_QUERY,
                description="websocket group name - user email",
                type=openapi.TYPE_STRING,
            ),
            openapi.Parameter(
                "response_type",
                openapi.IN_QUERY,
                description="websocket message type",
                type=openapi.TYPE_STRING,
            ),
            openapi.Parameter(
                "user_service_id",
                openapi.IN_QUERY,
                description="user service token uuid",
                type=openapi.TYPE_STRING,
            ),
        ],
        operation_summary="Send message to user", 
        operation_description="Send message to user through websocket.",
        operation_id="sendMessage",
        tags=["health"]
    )
    def get(self, request):
        """
        send message through websocket.

        Args:
            message (string): The message to send through socket.
            response_type (string): Yype message (eg: data_sync).
            group (string): Logged in user UUID.
            user_service_id(UUID): user service id of logged in user.

        Returns:
            None
        """
        try:

            message = request.GET.get('message')
            response_type = request.GET.get('response_type')
            group = request.GET.get('group')
            user_service_id = request.GET.get('user_service_id')
            
            channel_layer = get_channel_layer()
            message_json = {
                'message': message,
                'type': response_type
            }

            async_to_sync(channel_layer.group_send)(
                f"chat_{group}",
                {
                    'type': 'chat.message',
                    'data': message_json
                }
            )
            print("Notification sent successfully. ", message)
            return SuccessResponse(message="Notification send", data=[])
        except Exception as e:
            print("Notification sent failed", str(e))
            return ErrorResponse(message=str(e), status_code=status.HTTP_400_BAD_REQUEST)


class PrescriptionViewSet(viewsets.ModelViewSet):
    """
    Api for managing user prescriptions

    Methods:
        list (request): GET requests to retrieve list of prescriptions.
        create (request): Create requests to add a new prescription.
        update (request): Update request to update specific prescription.
        partial_update (request): Partial update request to partial update prescription by user.
        destroy (request): Destroy request to delete specific prescription by user.
    """
    queryset = Prescription.objects.all()
    serializer_class = PrescriptionSerializer
    permission_classes = [IsAuthenticated, HasActiveSubscription]

    
    def get_queryset(self):
        user = self.request.user
        if UserServiceToken.objects.filter(user=user,initial_sync=True).exists():
            return Prescription.objects.filter(user=user, deleted_at__isnull=True)
        return Prescription.objects.filter(user=user, deleted_at__isnull=True, is_self_created=True)

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="List Prescriptions", 
        operation_description="List prescriptions added by user.",
        operation_id="listPrescriptions",
        tags=["health"]
    )
    def list(self, request, *args, **kwargs):
        """
        Retrieves and returns a list of all prescriptions.

        Args:
            Default arguments.

        Returns:
            Response: A response containing a serialized list of prescriptions.
        """
        queryset = self.get_queryset()
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return SuccessResponse(message="Prescription list fetched successfully", data=serializer.data)

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Create Prescriptions", 
        operation_description="Create prescriptions by user.",
        operation_id="createPrescriptions",
        tags=["health"]
    )
    def create(self, request, *args, **kwargs):
        """
        Creates a new prescription.

        Args:
            request (Request): The HTTP request object containing prescription data.

        Returns:
            Response: A response with the created prescription details or an error message.
        """
        data = request.data
        data['is_self_created'] = True
        data['user'] = self.request.user.id
        serializer = self.get_serializer(data=data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return SuccessResponse(message="Prescription added successfully", data=serializer.data)
        return ErrorResponse(message="Prescription creation failed", status_code=status.HTTP_400_BAD_REQUEST,errors=serializer.errors)

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Update Prescriptions", 
        operation_description="Update prescriptions by user.",
        operation_id="updatePrescriptions",
        tags=["health"]
    )
    def update(self, request, *args, **kwargs):
        """
        Updates user prescription.

        Args:
            request (Request): The HTTP request object containing prescription data.

        Returns:
            Response: A response with the created prescription details or an error message.
        """
        instance = self.get_object()
        if instance.is_self_created:
            serializer = self.get_serializer(instance, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return SuccessResponse(message="Prescription updated successfully")
        return ErrorResponse(message="Prescription update failed", status_code=status.HTTP_400_BAD_REQUEST,errors=serializer.errors)
    

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Partial Update Prescriptions", 
        operation_description="Update prescriptions by user.",
        operation_id="partialUpdatePrescriptions",
        tags=["health"]
    )
    def partial_update(self, request, *args, **kwargs):
        """
        Updates user prescription only with the given values

        Args:
            request (Request): The HTTP request object containing prescription data.

        Returns:
            Response: A response with the created prescription details or an error message.
        """
        instance = self.get_object()
        if instance.is_self_created:
            serializer = self.get_serializer(instance, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return SuccessResponse(message="Prescription updated successfully")
        return ErrorResponse(message="Prescription update failed", status_code=status.HTTP_400_BAD_REQUEST,errors=serializer.errors)
        
    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Delete Prescriptions", 
        operation_description="Delete prescriptions by user.",
        operation_id="deletePrescriptions",
        tags=["health"]
    )
    def destroy(self, request, *args, **kwargs):
        """
        Deletes user prescription

        Args:
            id (UUID): Prescription UUID.

        Returns:
            Response: Succes message with 205 status
        """
        instance = self.get_object()
        instance.deleted_at = datetime.now()
        instance.save()
        return SuccessResponse(message="Prescription deleted successfully", status=status.HTTP_205_RESET_CONTENT)
    
    @swagger_auto_schema(auto_schema=None)
    def retrieve(self, request, *args, **kwargs):
        """
        Retrievs user prescription of given id

        Args:
            Default arguments

        Returns:
            None
        """
        raise NotFound("This endpoint is not available.")
    

class GeneralHealthView(GenericAPIView):
    """
    Api to handle personal info on questionnaire

    Methods:
        get(request): Handles GET requests to retrieve user personal info.
        post(request): Handles POST requests to create or update a user personal info.
    """

    queryset = PersonalInfo.objects.all()
    serializer_class = GeneralHealthSerializer
    pagination_class = None
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [IsAuthenticated, HasActiveSubscription]


    def get_queryset(self):
        user = self.request.user
        return PersonalInfo.objects.filter(user=user, deleted_at__isnull=True)
    
    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Get General Health", 
        operation_description="Retrieve general health details filled by user.",
        operation_id="getGeneralHealth",
        tags=["health"]
    )
    def get(self, request, *args, **kwargs):
        """
        Retrieves and returns user personal info.

        Args:
            request (Request): The HTTP request object.

        Returns:
            Response: A response containing a serialized list of user personal info.
        """
        try:
            obj_queryset = PersonalInfo.objects.filter(user=self.request.user, deleted_at__isnull=True).order_by('-created_at').first()
            serializer = self.get_serializer(obj_queryset)
            return SuccessResponse(message="General health details fetched successfully", data=serializer.data)
        except ObjectDoesNotExist:
            return SuccessResponse(message="No data found", data=[])
        except Exception as e:
            print(str(e))
            return ErrorResponse(message='Something went wrong', status_code=status.HTTP_400_BAD_REQUEST, errors=str(e))

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Post General Health", 
        operation_description="create/update general health details by user.",
        operation_id="postGeneralHealth",
        tags=["health"]
    )
    def post(self, request, *args, **kwargs):
        """
        Creates user personal info or, updates if already exists

        Args:
            request (Request): The HTTP request object containing product data.
            photo (file): Photo of insurance card

        Returns:
            Response: A response with the created personal info details or an error message.
        """
        try:
            request.data._mutable = True
            data = request.data
            data['user'] = self.request.user.id
            if 'photo' in request.data:
                data['file_name'] = request.data.get('photo').name
                mime_type, _ = mimetypes.guess_type(data['file_name'])
                if mime_type == "application/pdf":
                    request.data['photo'] = sanitize_pdf(request.data.get('photo'))

            obj_personalinfo = PersonalInfo.objects.filter(user=self.request.user, deleted_at__isnull=True)
            if obj_personalinfo:
                obj_personalinfo = obj_personalinfo.first()
                instance = obj_personalinfo
                if 'photo' in request.data and instance.photo:
                    # Delete the old file from S3
                    old_file_url = instance.photo.url
                    delete_file_from_s3(old_file_url)
                serializer = self.get_serializer(instance, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return SuccessResponse(message="Personal info updated successfully")
            else:
                serializer = self.get_serializer(data=data)
                if serializer.is_valid(raise_exception=True):
                    serializer.save()
                    return SuccessResponse(message="Personal info added successfully", data=serializer.data)
                
            return ErrorResponse(message='Personal info creation failed', status_code=status.HTTP_400_BAD_REQUEST, errors=serializer.errors)
        except Exception as e:
            print(str(e))
            return ErrorResponse(message='Something went wrong', status_code=status.HTTP_400_BAD_REQUEST, errors=str(e))
        

class QuestionnaireCount(APIView):
    """
    Api to get steps completed on questionnaire

    Methods:
        get(request): Handles GET requests to retrieve questionnaire tabs completion count.
        questionnaire_count: Calculates questionnaire tabs completion count based on data in db.
    """

    pagination_class = None
    
    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Get Questionnaire count", 
        operation_description="Get count of questionnaire steps completed by user.",
        operation_id="getQuestionnaireCount",
        tags=["health"]
    )
    def get(self, request, *args, **kwargs):
        """
        Retrieves questionnaire tabs completion count.

        Args:
            request (Request): The HTTP request object.

        Returns:
            data: Questionnaire count.
        """
        try:
            data = {}
            data = self.questionnaire_count(data)
            return SuccessResponse(message="Questionnaire count details", data=data)
        except ObjectDoesNotExist:
            return SuccessResponse(message="No data found", data=[])
        except Exception as e:
            print(str(e))
            return ErrorResponse(message='Something went wrong', status_code=status.HTTP_400_BAD_REQUEST, errors=str(e))
        
    def questionnaire_count(self, data):
        """
        Calculates questionnaire tabs completion based on data in db.

        Args:
            data (list): Empty list.

        Returns:
            data: Questionnaire count.
        """
        user = self.request.user
        filters = {'user': user, 'deleted_at__isnull': True}

        obj_goal = PersonalInfo.objects.filter(**filters, goal__isnull=False)
        obj_gender = PersonalInfo.objects.filter(**filters, gender__isnull=False)
        obj_personalinfo = PersonalInfo.objects.filter(
            **filters,
            birth_date__isnull=False,
            zip_code__isnull=False,
            feet__isnull=False,
            inches__isnull=False,
            weight__isnull=False
        )
        obj_insurance = PersonalInfo.objects.filter(
            **filters,
            insurance_company_name__isnull=False,
            insurance_no__isnull=False,
            sponsor_name__isnull=False,
            photo__isnull=False
        )
        obj_habits = PersonalInfo.objects.filter(
            **filters,
            is_smoker__isnull=False,
            exercise_frequency__isnull=False,
            excercise_activities__isnull=False,
            excercise_time__isnull=False
        )

        obj_serviceprovider = ServiceProvider.objects.filter(
            **filters,
            provider__isnull=False
        )

        obj_prescription = Prescription.objects.filter(
            **filters
        )
        obj_prescription_is_self_created = obj_prescription.filter(
            is_self_created = True
        )

        obj_documents = Document.objects.filter(
            **filters
        )
        obj_documents_is_self_created = obj_documents.filter(
            is_self_created = True
        )

        data['general_health_step_1'] = bool(obj_goal)
        data['general_health_step_2'] = bool(obj_gender)
        data['general_health_step_3'] = bool(obj_personalinfo)
        data['general_health_step_4'] = bool(obj_insurance)
        data['general_health_step_5'] = bool(obj_habits)
        data['medical_records'] = bool(obj_serviceprovider)
        data['prescriptions'] = bool(obj_prescription) if UserServiceToken.objects.filter(user=user,initial_sync=True).exists() or obj_prescription_is_self_created.exists() else False
        data['documents'] = bool(obj_documents) if UserServiceToken.objects.filter(user=user,initial_sync=True).exists() or obj_documents_is_self_created.exists() else False

        count = 0
        if (bool(obj_goal)==True and bool(obj_gender)==True and bool(obj_personalinfo)==True and bool(obj_insurance)==True and bool(obj_habits)==True):
            count += 1
        if (bool(obj_serviceprovider)==True):
            count += 1
        if (data['prescriptions']==True):
            count += 1
        if (data['documents'] == True):
            count += 1
        data['questionnaire_count'] = count
        return data

class AllergyViewSet(viewsets.ModelViewSet):
    """
    Api fo managing allergies data by user

    Methods:
        list(request): Handles GET requests to retrieve all allergies added by user.
        create(request): Adds new allergy by user.
        update(request): Updates existing allergy by user.
        partial_update(request): Updates existing allergy only based on the data provided.
        destroy(request): Deletes allergy added by user.
        retrieve(request):Retrievs user allergy of given id.
    """
    queryset = Allergy.objects.all()
    serializer_class = AllergySerializer
    parser_classes = [MultiPartParser]
    permission_classes = [IsAuthenticated, HasActiveSubscription]
    
    def get_queryset(self):
        user = self.request.user
        return Allergy.objects.filter(user=user, deleted_at__isnull=True)

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="List Allergies", 
        operation_description="List allergies added by user.",
        operation_id="listAllergies",
        tags=["health"]
    )
    def list(self, request, *args, **kwargs):
        """
        Retrieves and returns a list of allergies.

        Args:
            request (Request): The HTTP request object.

        Returns:
            Response: A response containing a serialized list of allergies.
        """
        queryset = self.get_queryset().order_by('created_at')
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return SuccessResponse(message="Allergy list fetched successfully", data=serializer.data)

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Create Allergies", 
        operation_description="Create allergies by user.",
        operation_id="createAllergies",
        tags=["health"]
    )
    def create(self, request, *args, **kwargs):
        """
        This function adds new allergy by user.

        Args:
            request (Request): The HTTP request object.
            file (file): pdf, jpeg or png image

        Returns:
            Response: A response with the created allergy details or an error message.
        """

        request.data._mutable = True
        request.data['user'] = self.request.user.id
        request.data['file_name'] = request.data['file'].name
        mime_type, _ = mimetypes.guess_type(request.data['file_name'])
        if mime_type == "application/pdf":
            request.data['file'] = sanitize_pdf(request.data.get('file'))
        request.data._mutable = False
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return SuccessResponse(message="Allergy added successfully", data=serializer.data)
        return ErrorResponse(message="Allergy creation failed", status_code=status.HTTP_400_BAD_REQUEST,errors=serializer.errors)

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Update Allergies", 
        operation_description="Update allergies by user.",
        operation_id="updateAllergies",
        tags=["health"]
    )
    def update(self, request, *args, **kwargs):
        """
        This function updates existing allergy by user.
        If any file exists in S3, it is deleted before uploading new file.

        Args:
            request (Request): The HTTP request object.
            file (file): pdf, jpeg or png image

        Returns:
            Response: A success response or an error message.
        """
        instance = self.get_object()
        if 'file' in request.data and instance.file:
            # Delete the old file from S3
            old_file_url = instance.file.url
            delete_file_from_s3(old_file_url)
            # Update file name
            request.data._mutable = True
            request.data['file_name'] = request.data['file'].name
            mime_type, _ = mimetypes.guess_type(request.data['file_name'])
            if mime_type == "application/pdf":
                request.data['file'] = sanitize_pdf(request.data.get('file'))
            request.data._mutable = False

        serializer = self.get_serializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return SuccessResponse(message="Allergy updated successfully")
        return ErrorResponse(message="Allergy update failed", status_code=status.HTTP_400_BAD_REQUEST,errors=serializer.errors)
    
    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Partial Update Allergies", 
        operation_description="Update allergies by user.",
        operation_id="partialUdateAllergies",
        tags=["health"]
    )
    def partial_update(self, request, *args, **kwargs):
        """
        This function partial updates existing allergy by user(only values passed are updated).
        If any file exists in S3, it is deleted before uploading new file.

        Args:
            request (Request): The HTTP request object.
            file (file): pdf, jpeg or png image

        Returns:
            Response: A success response or an error message.
        """
        instance = self.get_object()
        if 'file' in request.data and instance.file:
            # Delete the old file from S3
            old_file_url = instance.file.url
            delete_file_from_s3(old_file_url)
            # Update file name
            request.data._mutable = True
            request.data['file_name'] = request.data['file'].name
            mime_type, _ = mimetypes.guess_type(request.data['file_name'])
            if mime_type == "application/pdf":
                request.data['file'] = sanitize_pdf(request.data.get('file'))
            request.data._mutable = False

        serializer = self.get_serializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return SuccessResponse(message="Allergy updated successfully")
        return ErrorResponse(message="Allergy update failed", status_code=status.HTTP_400_BAD_REQUEST,errors=serializer.errors)
    
        
    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Delete Allergies", 
        operation_description="Delete allergies by user.",
        operation_id="deleteAllergies",
        tags=["health"]
    )
    def destroy(self, request, *args, **kwargs):
        """
        Deletes user allergy

        Args:
            id (UUID): Allergy UUID.

        Returns:
            Response: Succes message with 205 status
        """
        instance = self.get_object()
        instance.deleted_at = datetime.now()
        instance.save()
        return SuccessResponse(message="Allergy deleted successfully", status_code=status.HTTP_205_RESET_CONTENT)
    
    @swagger_auto_schema(auto_schema=None)
    def retrieve(self, request, *args, **kwargs):
        """
        Retrievs user allergy of given id

        Args:
            Default arguments

        Returns:
            None
        """
        raise NotFound("This endpoint is not available.")
    

class ImmunizationViewSet(viewsets.ModelViewSet):
    """
    This viewset contains api's for managing immunization data by user.

    Methods:
        list(request): Handles GET requests to retrieve all immunization added by user.
        create(request): Adds new immunization by user.
        update(request): Updates existing immunization by user.
        partial_update(request): Updates existing immunization only based on the data provided.
        destroy(request): Deletes immunization added by user.
        retrieve(request):Retrievs user immunization of given id.
    """
    queryset = Immunization.objects.all()
    serializer_class = ImmunizationSerializer
    parser_classes = [MultiPartParser]
    permission_classes = [IsAuthenticated, HasActiveSubscription]
    
    def get_queryset(self):
        user = self.request.user
        return Immunization.objects.filter(user=user, deleted_at__isnull=True)

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="List Immunization", 
        operation_description="List immunization details added by user.",
        operation_id="listImmunization",
        tags=["health"]
    )
    def list(self, request, *args, **kwargs):
        """
        Retrieves and returns a list of immunization.

        Args:
            request (Request): The HTTP request object.

        Returns:
            data: A response containing a serialized list of immunization.
        """
        queryset = self.get_queryset().order_by('created_at')
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return SuccessResponse(message="Immunization list fetched successfully", data=serializer.data)

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Create Immunization", 
        operation_description="Create immunization details by user.",
        operation_id="createImmunization",
        tags=["health"]
    )
    def create(self, request, *args, **kwargs):
        """
        This function adds new immunization by user.

        Args:
            request (Request): The HTTP request object.
            file (file): pdf, jpeg or png image

        Returns:
            data: A response with the created immunization details or an error message.
        """
        request.data._mutable = True
        request.data['user'] = self.request.user.id
        request.data['file_name'] = request.data['file'].name
        mime_type, _ = mimetypes.guess_type(request.data['file_name'])
        if mime_type == "application/pdf":
            request.data['file'] = sanitize_pdf(request.data.get('file'))
        request.data._mutable = False
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return SuccessResponse(message="Immunization added successfully", data=serializer.data)
        return ErrorResponse(message="Immunization creation failed", status_code=status.HTTP_400_BAD_REQUEST,errors=serializer.errors)

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Update Immunization", 
        operation_description="Update immunization details by user.",
        operation_id="updateImmunization",
        tags=["health"]
    )
    def update(self, request, *args, **kwargs):
        """
        This function updates existing immunization by user.
        If any file exists in S3, it is deleted before uploading new file.

        Args:
            request (Request): The HTTP request object.
            file (file): pdf, jpeg or png image

        Returns:
            Response: A success response or an error message.
        """
        instance = self.get_object()
        if 'file' in request.data and instance.file:
            # Delete the old file from S3
            old_file_url = instance.file.url
            delete_file_from_s3(old_file_url)
            # Update file name
            request.data._mutable = True
            request.data['file_name'] = request.data['file'].name
            mime_type, _ = mimetypes.guess_type(request.data['file_name'])
            if mime_type == "application/pdf":
                request.data['file'] = sanitize_pdf(request.data.get('file'))
            request.data._mutable = False

        serializer = self.get_serializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return SuccessResponse(message="Immunization updated successfully")
        return ErrorResponse(message="Immunization update failed", status_code=status.HTTP_400_BAD_REQUEST,errors=serializer.errors)
    

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Partial Update Immunization", 
        operation_description="Update immunization details by user.",
        operation_id="partialUpdateImmunization",
        tags=["health"]
    )
    def partial_update(self, request, *args, **kwargs):
        """
        This function partial updates existing immunization by user(only values passed are updated).
        If any file exists in S3, it is deleted before uploading new file.

        Args:
            request (Request): The HTTP request object.
            file (file): pdf, jpeg or png image

        Returns:
            Response: A success response or an error message.
        """
        instance = self.get_object()
        if 'file' in request.data and instance.file:
            # Delete the old file from S3
            old_file_url = instance.file.url
            delete_file_from_s3(old_file_url)
            # Update file name
            request.data._mutable = True
            request.data['file_name'] = request.data['file'].name
            mime_type, _ = mimetypes.guess_type(request.data['file_name'])
            if mime_type == "application/pdf":
                request.data['file'] = sanitize_pdf(request.data.get('file'))
            request.data._mutable = False
            
        serializer = self.get_serializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return SuccessResponse(message="Immunization updated successfully")
        return ErrorResponse(message="Immunization update failed", status_code=status.HTTP_400_BAD_REQUEST,errors=serializer.errors)
        
    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Delete immunization", 
        operation_description="Delete immunization details by user.",
        operation_id="deleteImmunization",
        tags=["health"]
    )
    def destroy(self, request, *args, **kwargs):
        """
        Deletes user immunization

        Args:
            id (UUID): Immunization UUID.

        Returns:
            Response: Succes message with 205 status
        """
        instance = self.get_object()
        instance.deleted_at = datetime.now()
        instance.save()
        return SuccessResponse(message="Immunization deleted successfully", status_code=status.HTTP_205_RESET_CONTENT)
    
    @swagger_auto_schema(auto_schema=None)
    def retrieve(self, request, *args, **kwargs):
        """
        Retrievs user immunization of given id

        Args:
            Default arguments

        Returns:
            None
        """
        raise NotFound("This endpoint is not available.")

class GeneralHealthMasterData(APIView):
    permission_classes = [IsAuthenticated, HasActiveSubscription]

    """
    Api to load master data for questionnaire general health section

    Methods:
        get(request): Handles GET requests to retrieve all master data.
        get_formated_list(request): Format data to suitable list format.
    """

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Get Master Data", 
        operation_description="Get master data list.",
        operation_id="getMasterData",
        tags=["health"]
    )
    def get(self, request):
        """
        Retrieves and returns a list of allergies.

        Args:
            request (Request): The HTTP request object.

        Returns:
            Response: A response containing a list of master data.
        """

        try:
            data = {}
            obj_personal_info = PersonalInfo()
            obj_document_info = Document()
            data['gender'] = self.get_formated_list(list(obj_personal_info._meta.get_field('gender').choices))
            data['excercise_time'] =   self.get_formated_list(list(obj_personal_info._meta.get_field('excercise_time').choices))
            data['exercise_frequency'] =   self.get_formated_list(list(obj_personal_info._meta.get_field('exercise_frequency').choices))
            data['excercise_activities'] =   self.get_formated_list(ALLOWED_EXCERCISE_CHOICES)
            data['goals'] =   self.get_formated_list(ALLOWED_GOALS_CHOICES)
            data['current_health'] = self.get_formated_list(list(obj_personal_info._meta.get_field('current_health').choices))
            data['intensity_of_excercise'] = self.get_formated_list(list(obj_personal_info._meta.get_field('intensity_of_excercise').choices))
            data['symptom'] = self.get_formated_list(list(obj_personal_info._meta.get_field('symptom').choices))
            data['document'] = self.get_formated_list(list(obj_document_info._meta.get_field('category').choices))
            return SuccessResponse(message="General health master data", data=data)
            
        except Exception as e:
            return ErrorResponse(message=str(e), status_code=status.HTTP_400_BAD_REQUEST)
    
    def get_formated_list(self, lst_values):
        """
        Retrieves and returns a list of allergies.

        lst_values:
            request (Request): List of data to be formatted.

        Returns:
            Response: A response containing a list of master data.
        """
        return [{"value": item[0], "display": item[1]} for item in lst_values]


class ProfileAdditionalInfoView(GenericAPIView):
    """
    Api to handle additional info on profile

    Methods:
        get(request): Handles GET requests to retrieve additional info added by user.
        post(request): Handles POST requests to add or update profile additional info.
    """

    queryset = PersonalInfo.objects.all()
    serializer_class = ProfileAdditionalInfoSerializer
    pagination_class = None

    def get_queryset(self):
        user = self.request.user
        return PersonalInfo.objects.filter(user=user, deleted_at__isnull=True)
    
    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Get Profile Additional Info", 
        operation_description="Get profile additional info.",
        operation_id="getProfileAdditionalInfo",
        tags=["health"]
    )
    def get(self, request, *args, **kwargs):
        """
        Retrieves and returns additional info added by user.

        Args:
            request (Request): The HTTP request object.

        Returns:
            Response: A response containing a serialized list of profile additional info.
        """
        try:
            obj_queryset = PersonalInfo.objects.filter(user=self.request.user, deleted_at__isnull=True).order_by('-created_at').first()
            serializer = self.get_serializer(obj_queryset)
            return SuccessResponse(message="Additional info fetched successfully", data=serializer.data)
        except ObjectDoesNotExist:
            return SuccessResponse(message="No data found", data=[])
        except Exception as e:
            print(str(e))
            return ErrorResponse(message='Something went wrong', status_code=status.HTTP_400_BAD_REQUEST, errors=str(e))

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Post Profile Additional Info", 
        operation_description="Post profile additional info.",
        operation_id="postProfileAdditionalInfo",
        tags=["health"]
    )
    def post(self, request, *args, **kwargs):
        """
        Add or update profile additional info.

        Args:
            request (Request): The HTTP request object containing product data.

        Returns:
            Response: A success response or an error message.
        """
        try:
            data = request.data
            data['user'] = self.request.user.id
            obj_personalinfo = PersonalInfo.objects.filter(user=self.request.user, deleted_at__isnull=True)
            if obj_personalinfo:
                instance = obj_personalinfo.first()
                serializer = self.get_serializer(instance, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return SuccessResponse(message="Additional info updated successfully")
            else:
                serializer = self.get_serializer(data=data)
                if serializer.is_valid(raise_exception=True):
                    serializer.save()
                    return SuccessResponse(message="Additional info added successfully")
                
            return ErrorResponse(message='Additional info creation failed', status_code=status.HTTP_400_BAD_REQUEST, errors=serializer.errors)
        except Exception as e:
            print(str(e))
            return ErrorResponse(message='Something went wrong', status_code=status.HTTP_400_BAD_REQUEST, errors=str(e))
        

class DocumentViewSet(viewsets.ModelViewSet):
    """
    Api for managing user documents

    Methods:
        list(request): Handles GET requests to retrieve all documents added by user.
        create(request): Adds new document by user.
        update(request): Updates existing document by user.
        partial_update(request): Updates existing document only based on the data provided.
        destroy(request): Deletes document added by user.
        retrieve(request):Retrievs user document of given id.
    """
    queryset = Document.objects.all()
    serializer_class = DocumentSerializer
    parser_classes = [MultiPartParser]
    permission_classes = [IsAuthenticated, HasActiveSubscription]
    filter_backends = [DjangoFilterBackend]
    filterset_class = DocumentFilter
    
    def get_queryset(self):
        user = self.request.user
        if UserServiceToken.objects.filter(user=user, initial_sync=True).exists():
            return Document.objects.filter(user=user, deleted_at__isnull=True)
        return Document.objects.filter(user=user, deleted_at__isnull=True, is_self_created=True)
    
    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="List Documents", 
        operation_description="List documents added by user.",
        operation_id="listDocuments",
        tags=["health"]
    )
    def list(self, request, *args, **kwargs):
        """
        Retrieves and returns a list of documents.

        Args:
            request (Request): The HTTP request object.

        Returns:
            Response: A response containing a serialized list of documents.
        """
        queryset = self.get_queryset().order_by('created_at')
        category = request.query_params.get('category', None)
        if category:
            queryset = queryset.filter(category=category)
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return SuccessResponse(message="Document list fetched successfully", data=serializer.data)

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Create Document", 
        operation_description="Add new document for user.",
        operation_id="createDocument",
        tags=["health"]
    )
    def create(self, request, *args, **kwargs):
        """
        This function adds new document for user.

        Args:
            request (Request): The HTTP request object.
            files (file): pdf, jpeg or png image

        Returns:
            Response: A response with the created document details or an error message.
        """
        try:
            request.data._mutable = True
            request.data['user'] = self.request.user.id
            request.data['is_self_created'] = True
            request.data['file_name'] = request.data['files'].name
            mime_type, _ = mimetypes.guess_type(request.data['file_name'])
            if mime_type == "application/pdf":
                request.data['files'] = sanitize_pdf(request.data.get('files'))
            request.data._mutable = False

            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return SuccessResponse(message="Document added successfully", data=serializer.data)

            return ErrorResponse(
                message="Document creation failed", 
                status_code=status.HTTP_400_BAD_REQUEST,
                errors=serializer.errors
            )

        except (NoCredentialsError, PartialCredentialsError) as e:
            return ErrorResponse(
                message="AWS credentials error", 
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                errors=str(e)
            )

        except Exception as e:
            return ErrorResponse(
                message="An unexpected error occurred", 
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                errors=str(e)
            )

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Update Document", 
        operation_description="Update user documents.",
        operation_id="updateDocument",
        tags=["health"]
    )
    def update(self, request, *args, **kwargs):
        """
        This function updates existing user document.
        If any file exists in S3, it is deleted before uploading new file.

        Args:
            request (Request): The HTTP request object.
            files (file): pdf, jpeg or png image

        Returns:
            Response: A success response or an error message.
        """
        instance = self.get_object()
        if instance.is_self_created:
            if 'files' in request.data and instance.files:
                request.data._mutable = True
                # Delete the old file from S3
                old_file_url = instance.files.url
                delete_file_from_s3(old_file_url)
                request.data['file_name'] = request.data['files'].name
                mime_type, _ = mimetypes.guess_type(request.data['file_name'])
                if mime_type == "application/pdf":
                    request.data['files'] = sanitize_pdf(request.data.get('files'))
                request.data._mutable = False
            serializer = self.get_serializer(instance, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return SuccessResponse(message="Document updated successfully")
        return ErrorResponse(message="Document update failed", status_code=status.HTTP_400_BAD_REQUEST,errors=serializer.errors)
    

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Partial Update Document", 
        operation_description="Update user documents.",
        operation_id="partialUpdateDocument",
        tags=["health"]
    )
    def partial_update(self, request, *args, **kwargs):
        """
        This function partial updates existing document for user(only values passed are updated).
        If any file exists in S3, it is deleted before uploading new file.

        Args:
            request (Request): The HTTP request object.
            file (file): pdf, jpeg or png image

        Returns:
            Response: A success response or an error message.
        """
        instance = self.get_object()
        if instance.is_self_created:
            if 'files' in request.data and instance.files:
                request.data._mutable = True
                # Delete the old file from S3
                old_file_url = instance.files.url
                delete_file_from_s3(old_file_url)
                request.data['file_name'] = request.data['files'].name
                mime_type, _ = mimetypes.guess_type(request.data['file_name'])
                if mime_type == "application/pdf":
                    request.data['files'] = sanitize_pdf(request.data.get('files'))
                request.data._mutable = False
            serializer = self.get_serializer(instance, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return SuccessResponse(message="Document updated successfully")
        return ErrorResponse(message="Document update failed", status_code=status.HTTP_400_BAD_REQUEST,errors=serializer.errors)
    
        
    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Delete Document", 
        operation_description="Delete user document.",
        operation_id="deleteDocument",
        tags=["health"]
    )
    def destroy(self, request, *args, **kwargs):
        """
        Deletes user document

        Args:
            id (UUID): document UUID.

        Returns:
            Response: Succes message with 205 status
        """
        instance = self.get_object()
        instance.deleted_at = datetime.now()
        instance.save()
        return SuccessResponse(message="Document deleted successfully", status_code=status.HTTP_205_RESET_CONTENT)
    
    @swagger_auto_schema(auto_schema=None)
    def retrieve(self, request, *args, **kwargs):
        """
        Retrievs user document of given id

        Args:
            Default arguments

        Returns:
            None
        """
        raise NotFound("This endpoint is not available.")


class ConnectedProviders(GenericAPIView):
    """
    Api to get list of connected providers by a user

    Methods:
        get(request): Handles GET requests to list the providers connected by user
    """
    serializer_class = ConnectedProvidersSerializer
    pagination_class = None
    permission_classes = [IsAuthenticated, HasActiveSubscription]

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="List Connected Providers", 
        operation_description="List all the providers connected by user.",
        operation_id="listConnectedProviders",
        tags=["health"]
    )
    def get(self, request):
        """
        Retrieves and returns a list of providers connected by logged in user.

        Args:
            request (Request): The HTTP request object.

        Returns:
            Response: A response containing a serialized list of providers.
        """
        try:
            user = self.request.user
            obj_queryset = ServiceProvider.objects.filter(user=user, deleted_at__isnull=True)
            if obj_queryset.exists():
                serializer = self.get_serializer(obj_queryset, many=True)
                return SuccessResponse(message="Connected providers list", data=serializer.data)
            else:
                return SuccessResponse(message="Connected providers list", data=[])
        except Exception as e:
            print(str(e))
            return ErrorResponse(message='Something went wrong', status_code=status.HTTP_400_BAD_REQUEST, errors=str(e))
        

class VisitsListAPIView(ListAPIView):
    """
    Api to list visits/encounters

    Methods:
        get(request): Handles GET requests to retrieve all visits/encounters
    """
    queryset = Encounter.objects.all()
    serializer_class = EncounterSerializer
    filter_backends = [DjangoFilterBackend]
    permission_classes = [IsAuthenticated, HasActiveSubscription]
    filterset_class = EncounterFilter
    def get_queryset(self):
        user = self.request.user
        if UserServiceToken.objects.filter(user=self.request.user,initial_sync=True).exists():
            return Encounter.objects.filter(user=user, deleted_at__isnull=True).order_by(self.request.GET.get('ordering'), 'id')
        return Encounter.objects.none()
    
    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="List Visits", 
        operation_description="List visits added by user.",
        operation_id="listVisits",
        tags=["health"]
    )
    def get(self, request, *args, **kwargs):
        """
        Retrieves and returns a list of visits/encounters.

        Args:
            request (Request): The HTTP request object.

        Returns:
            Response: A response containing a serialized list of visits.
        """
        return super().get(request, *args, **kwargs)


class ConditionsListAPIView(ListAPIView):
    """
    Api to list conditions added by user

    Methods:
        get(request): Handles GET requests to retrieve all conditions added by user.
    """
    queryset = Condition.objects.all()
    serializer_class = ConditionSerializer
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    ordering_fields = ['record_synced_at']
    permission_classes = [IsAuthenticated, HasActiveSubscription]

    def get_queryset(self):
        user = self.request.user
        if UserServiceToken.objects.filter(user=self.request.user,initial_sync=True).exists():
            return Condition.objects.filter(user=user, deleted_at__isnull=True)
        return Condition.objects.none()

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="List Conditions", 
        operation_description="List conditions added by user.",
        operation_id="listConditions",
        tags=["health"]
    )
    def get(self, request, *args, **kwargs):
        """
        Retrieves and returns a list of conditions added by user.

        Args:
            request (Request): The HTTP request object.

        Returns:
            Response: A response containing a serialized list of conditions conditions.
        """
        return super().get(request, *args, **kwargs)


class ViewDocumentAPI(APIView):
    """
    Api to view documents added. Retrievs document URL from AWS S3 and return a presigned URL

    Methods:
        get(request): Handles GET requests to retrieve all documents added by user.
    """
    permission_classes = [IsAuthenticated]
    queryset = Document.objects.all()
    permission_classes = [IsAuthenticated, HasActiveSubscription]

    @swagger_auto_schema(
        manual_parameters=[],
        operation_summary="Get Document Url", 
        operation_description="Get S3 url of given document uuid.",
        operation_id="getDocumentUrl",
        tags=["health"]
    )
    def get(self, request, doc_id):
        """
        Retrieves and returns a list of documents.

        Args:
            request (Request): The HTTP request object.

        Returns:
            Response: A response containing a serialized list of documents.
        """
        try:
            # Get the document instance
            document = self.queryset.filter(user=self.request.user, deleted_at__isnull=True).get(id=doc_id)

            if not document.files:
                return ErrorResponse(error ="No file associated with this document.", status=status.HTTP_404_NOT_FOUND)

            # Initialize boto3 S3 client
            s3_client = boto3.client(
                's3',
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region_name=settings.AWS_S3_REGION_NAME,
                config=Config(signature_version=settings.AWS_S3_SIGNATURE_VERSION)  # Explicitly use Signature Version 4
            )
            # Generate pre-signed URL for the file
            bucket_name = settings.AWS_STORAGE_BUCKET_NAME
            file_key = document.files.name

            presigned_url = s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': bucket_name, 'Key': file_key},
                ExpiresIn=3600
            )
            return SuccessResponse(message="Success", data={"url": presigned_url})

        except Document.DoesNotExist:
            return ErrorResponse(error="Document not found.", status=status.HTTP_404_NOT_FOUND)
        except (NoCredentialsError, PartialCredentialsError):
            return ErrorResponse(error="Invalid AWS credentials.", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return ErrorResponse(error=str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DataSyncRefresh(APIView):
    """
    Api to initiate 1UP data sync refresh. 

    Methods:
        get(request): Handles GET requests to initiate 1UP data sync refresh.
    """
    permission_classes = [IsAuthenticated, HasActiveSubscription]

    @swagger_auto_schema(
            operation_summary="1UP data sync refresh", 
            operation_description="1UP data sync refresh"
            )
    def get(self, request):
        """
        Checks if any background task is running. If none, then a new background refresh is initiated for user.

        Args:
            request (Request): The HTTP request object.

        Returns:
            Response: Success message depending on new task started or previous one exists.
        """
        try:
            obj_servicetoken = UserServiceToken.objects.filter(user=self.request.user)
            if obj_servicetoken.filter(sync_status="processing").exists():
                return SuccessResponse(message="Active background sync found", data={"background_sync_status": True})
            user_service_token_obj = obj_servicetoken.first()
            if user_service_token_obj:
                user_service_token_obj = UserServiceToken.objects.filter(user=self.request.user).get()
                user_service_id = user_service_token_obj.id
                send_task_on_provider_connect(user_service_id, is_initial_provider_sync=False)
                return SuccessResponse(message="Background sync started", data={"background_sync_status": True})
            return ErrorResponse(message='Background sync failed', status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(str(e))
            return ErrorResponse(error=str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DashboardRefreshDetails(APIView):
    """
    Api to get background sync status and last successful sync date and time

    Methods:
        get(request): Handles GET requests to fetch 1UP data sync background task status and last refresh date.
    """
    permission_classes = [IsAuthenticated, HasActiveSubscription]

    @swagger_auto_schema(
            operation_summary="Get last refresh date and background sync status", 
            operation_description="Get last refresh date and background sync status"
            )
    def get(self, request):
        """
        Retrieves 1UP data sync background task status and last refresh date.

        Args:
            request (Request): The HTTP request object.

        Returns:
            data: A response containing background sync status and last refresh date.
        """
        try:
            data = {}
            data['refresh_date'] = None
            data['background_sync_status'] = False
            obj_servicetoken = UserServiceToken.objects.filter(user=self.request.user)
            if obj_servicetoken.filter(sync_status="processing").exists():
                data['background_sync_status'] = True
            user_service_token_obj = obj_servicetoken.first()
            if user_service_token_obj:
                data['refresh_date'] = user_service_token_obj.last_sync_date
                return SuccessResponse(message="Background sync last refresh date", data=data)
            else:
                return ErrorResponse(message='No data found', status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(str(e))
            return ErrorResponse(error=str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)