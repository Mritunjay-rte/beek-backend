import requests
from datetime import datetime
from decouple import config
from health.models import Encounter, DataSyncLog, Document, Prescription, Condition, UserServiceToken, DataSyncExceptionLog,\
                            ExternalAPILog
from health.tasks import process_condition_data, process_encounter_data, process_medication_request_data, process_document_reference_data
from django.db.models import F
from django.core.files.base import ContentFile
import base64
import time
from django.utils import timezone
from decouple import config
from health.utils import save_encounter_bulk_export, save_condition_bulk_export, save_document_reference_bulk_export, save_medication_request_bulk_export
import threading


_1UP_CLIENT_ID = config('1UP_CLIENT_ID')
_1UP_CLIENT_SECRET = config('1UP_CLIENT_SECRET')

GENERATE_AUTH_CODE_URL = config('GENERATE_AUTH_CODE_URL')
GENERATE_ACCESS_TOKEN_URL = config('GENERATE_ACCESS_TOKEN_URL')
BULK_DATA_EXPORT_URL = config('BULK_DATA_EXPORT_URL')
BEEK_NOTIFICATION_API = config('BEEK_NOTIFICATION_API')
DELAY_TIME_IN_SEC = config('DELAY_TIME_IN_SEC', '10')

MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds

def retry_on_failure(func):
    """
    A decorator that retries the decorated function upon failure up to a maximum 
    number of attempts (MAX_RETRIES).

    If the function fails after the maximum retries, it logs the failure, updates 
    the user service sync status to 'failed', and sends a socket message.

    Args:
        func (function): The function to be decorated, which will be retried on failure.

    Returns:
        function: The wrapper function that handles retries and failure logging.
    """

    def wrapper(*args, **kwargs):
        retry = 0
        error_message = ""
        while retry < MAX_RETRIES:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_message = f"Attempt {retry + 1}: Error occurred - {str(e)}"
                print(error_message)
                retry += 1
                time.sleep(RETRY_DELAY)
        # Log failure after max retries
        user_service = args[0]
        task_id = args[1]
        log_failure(task_id=task_id, user_service=user_service, error_message=error_message)
        
        message = str(user_service.service.name)+ "sync failed"
        user_service.sync_status = 'failed'
        user_service.save()
        send_socket_message(user_service.user.id, message, user_service.id)

    return wrapper


def log_failure(task_id, user_service, error_message):
    """
    Log the failure of a data synchronization task.

    This function records details of a failed task, including the task ID, user service 
    information, and the error message, in the `DataSyncExceptionLog` model. It helps 
    track failures for debugging, auditing, and analysis.

    Args:
        task_id (str): The unique identifier for the synchronization task.
        user_service (UserServiceToken): The user service object related to the failed task.
        error_message (str): The error message associated with the failure.

    Returns:
        int: Returns 1 to indicate that the failure has been logged.
    """
   
    if user_service:
        user_id = str(user_service.user.id)
        service_id = str(user_service.id)
    else:
        user_id = ''
        service_id = ''
    DataSyncExceptionLog.objects.create(
        task_id=task_id,
        payload={
            "user_id": user_id,
            "service_id": service_id,
            "error": error_message
        }
    )
    return 1


def api_log(user_service, api_endpoint, is_success_response, is_initial_sync, error_message=None):
    """
    Log the details of an external API interaction.

    This function records the details of an API call, including the user service, 
    endpoint, response status, and any error messages, in the `ExternalAPILog` model.

    Args:
        user_service (UserServiceToken): The user service object associated with the API call.
        api_endpoint (str): The endpoint of the external API being interacted with.
        is_success_response (bool): A flag indicating whether the API response was successful.
        is_initial_sync (bool): A flag indicating whether the interaction is part of an initial sync.
        error_message (str, optional): The error message if the API call failed. Defaults to None.

    Returns:
        int: Returns 1 to indicate that the API interaction details have been logged.
    """

    ExternalAPILog.objects.create(
        user_service=user_service,
        user=user_service.user,
        api_endpoint=api_endpoint,
        is_success_response=is_success_response,
        error_message={"error": error_message} if error_message else None,
        is_initial_sync=is_initial_sync
    )
    
    return 1


@retry_on_failure
def generate_authorization_code(user_service, task_id, is_initial_provider_sync):
    """
    Generate an authorization code for a user.

    This function interacts with the 1Up Health external API to generate a unique 
    authorization code for the specified user. It constructs the necessary parameters, 
    including the user ID, client ID, and client secret, and sends a POST request to 
    the API endpoint. If successful, the generated authorization code is saved to the user 
    service and triggers the next step in the authentication flow(generate_access_token_by_code).

    Args:
        user_service (UserServiceToken): The user service object associated with the request.
        task_id (str): The unique identifier for the synchronization task.
        is_initial_provider_sync (bool): Flag indicating whether this is an initial sync for the provider.

    Returns:
        bool: Returns True if the authorization code is successfully generated and saved, False otherwise.

    """

    params = {
        "app_user_id": str(user_service.user.id),
        "client_id": _1UP_CLIENT_ID,
        "client_secret": _1UP_CLIENT_SECRET,
    }

    try:
        response = requests.post(GENERATE_AUTH_CODE_URL, params=params)
        if response.status_code == 200:
            data = response.json()
            code = data.get("code")
            if code:
                user_service.code = code
                user_service.save()
                api_log(user_service, GENERATE_AUTH_CODE_URL, True, is_initial_provider_sync, None)
                generate_access_token_by_code(user_service, task_id, is_initial_provider_sync)
                return True
            else:
                error_message=f"Exception in generate code: {response.text}"
                api_log(user_service, GENERATE_AUTH_CODE_URL, False, is_initial_provider_sync, error_message)
                log_failure(task_id, user_service, error_message)

        else:
            error_message=f"Failed to generate authorization code: {response.text}"
            api_log(user_service, GENERATE_AUTH_CODE_URL, False, is_initial_provider_sync, error_message)
            raise Exception(f"Failed to generate authorization code")
    except Exception as e:
        raise

   

def generate_access_token_by_code(user_service, task_id, is_initial_provider_sync):
    """
    Generate an access token using an authorization code.

    This function uses 1Up Health authorization code for an access token 
    and a refresh token. It sends a POST request to the token endpoint with the 
    required credentials and authorization code. If successful, the access and 
    refresh tokens are stored in the user service object.

    Args:
        user_service (UserServiceToken): The user service object associated with the user.
        task_id (str): The unique identifier for the synchronization task being executed.
        is_initial_provider_sync (bool): Flag indicating whether this is part of the initial provider sync.

    Returns:
        bool: Returns True if the access token is successfully generated and stored. 
              If the request fails, it retries by generating a new authorization code.
    """

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    body = {
        "code": user_service.code,
        "grant_type":"authorization_code",
        "client_id": _1UP_CLIENT_ID,
        "client_secret": _1UP_CLIENT_SECRET,
    }
    response = requests.post(GENERATE_ACCESS_TOKEN_URL, headers=headers, data=body)
    if response.status_code == 200:
        data = response.json()
        user_service.access_token =  data["access_token"]
        user_service.refresh_token = data["refresh_token"]
        user_service.save()
        api_log(user_service, GENERATE_ACCESS_TOKEN_URL, True, is_initial_provider_sync, None)
        return True
    else:
        error_message = f"Exception in generate access token by code: {response.text}"
        api_log(user_service, GENERATE_ACCESS_TOKEN_URL, False, is_initial_provider_sync, error_message)
        log_failure(task_id, user_service, error_message)
        return generate_authorization_code(user_service, task_id, is_initial_provider_sync)
        

def generate_access_token_by_refresh_token(user_service, task_id, is_initial_provider_sync):
    """
    Generate a new access token using a refresh token.

    This function utilizes a refresh token to obtain a new access token for the 
    specified user. It interacts with an external API to perform the token 
    refresh process and ensures the user service remains authenticated.

    Args:
        user_service (UserServiceToken): The user service object associated with the user.
        task_id (str): The unique identifier for the synchronization task being executed.
        is_initial_provider_sync (bool): Flag indicating whether this is part of the initial provider sync.

    Returns:
        int: Returns 1 after successfully refreshing the token or logging the failure.

    """

    refresh_token = user_service.refresh_token

    data = {
        "refresh_token": refresh_token,
        "client_id": _1UP_CLIENT_ID,
        "client_secret": _1UP_CLIENT_SECRET,
        "grant_type":"refresh_token",
    }
    response = requests.post(GENERATE_ACCESS_TOKEN_URL, data=data)
    if response.status_code == 200:
        data = response.json()
        user_service.access_token =  data["access_token"]
        user_service.refresh_token = data["refresh_token"]
        user_service.save()
        api_log(user_service, GENERATE_ACCESS_TOKEN_URL, True, is_initial_provider_sync, None)
    else:
        error_message = f"Exception in generate access token by refresh token: {response.text}"
        api_log(user_service, GENERATE_ACCESS_TOKEN_URL, False, is_initial_provider_sync, error_message)
        log_failure(task_id, user_service, error_message)
    return 1


def load_user_service_data(user_service_id, task_id, is_initial_provider_sync):
    """
    Load user service data and initiate data synchronization.

    This function fetches the `UserServiceToken` for the given `user_service_id`, 
    generates an access token using the associated authorization code, and initiates 
    the process of fetching bulk export data. If the access token generation fails, 
    it logs the failure and updates the user's sync status.

    Args:
        user_service_id (int): The ID of the user service token to process.
        task_id (str): The unique identifier for the synchronization task.
        is_initial_provider_sync (bool): Indicates whether this is part of the initial provider sync.

    Process:
        1. Retrieves the `UserServiceToken` for the given ID.
        2. Generates an access token using the `generate_access_token_by_code` function.
        3. Sets the sync status to 'processing' and introduces a delay to allow 
           the provider's data to sync with the 1Up Health database, based on the configured delay time.
        4. Initiates the process of fetching bulk export data via `get_bulk_export_data`.
        5. On failure, logs the issue, updates sync status to 'failed', and sends a socket message.
    
    Returns:
        int: Returns 1 after success or logging the failure.

    """

    try:
        user_service = UserServiceToken.objects.filter(id=user_service_id).first()

        if not user_service:
            raise Exception(f"Service with ID {user_service_id} not found.")

        token = generate_access_token_by_code(user_service, task_id, is_initial_provider_sync)
        if token:
            user_service.sync_status = 'processing'
            user_service.save()
            # Set delay for fetching data from the provider to 1up
            time.sleep(int(DELAY_TIME_IN_SEC)) 
            get_bulk_export_data(user_service, task_id, is_initial_provider_sync)
        else:
            log_failure(task_id, user_service, error_message="Failed to generate access token")

            message = str(user_service.service.name)+ "sync failed due to failure in generating access token." 
            user_service.sync_status = 'failed'
            user_service.save()
            send_socket_message(user_service.user.id, message, user_service.id)

        
    except Exception as e:
        DataSyncExceptionLog.objects.create(
            task_id=task_id,
            payload={
                "user_id": "",
                "service_id": str(user_service_id),
                "error": str(e)
            }
        )

    return 1
    


def fetch_api_data(user_service, task_id, url, is_initial_provider_sync):
    """
    Fetches data from an API endpoint.

    Args:
        user_service (UserService): The user service object containing access token information.
        task_id (str): The ID of the task invoking this function.
        url (str): The API endpoint to fetch data from.
        is_initial_provider_sync (bool): Indicates whether the request is part of an initial provider sync process.

    Returns:
        requests.Response: The HTTP response object from the API call.
    """

    try:
        access_token = user_service.access_token
    
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            api_log(user_service, url, True, is_initial_provider_sync, None)
            return response
        
        elif response.status_code == 401:
            api_log(user_service, url, False, is_initial_provider_sync, error_message=f"Exception: {response.text}")
            generate_access_token_by_refresh_token(user_service, task_id, is_initial_provider_sync)
            # Update headers with the refreshed token
            access_token = user_service.access_token
            headers['Authorization'] = f'Bearer {access_token}'
            
            # Make the second call after refreshing token
            second_response = requests.get(url, headers=headers)
            if second_response.status_code == 200:
                api_log(user_service, url, True, is_initial_provider_sync, None)
            else:
                api_log(user_service, url, False, is_initial_provider_sync, error_message=f"Exception: {second_response.text}")
            return second_response
        
        else:
            # Raise any other errors to trigger retries
            api_log(user_service, url, False, is_initial_provider_sync, error_message=f"Exception on fetch API: : {response.text}")
            log_failure(task_id, user_service, error_message=f"fetch_api_data error: user_service:{user_service}, task_id:{task_id}, url:{url} Unexpected status code: {response.text}")
            return True

    except Exception as e:
        log_failure(task_id, user_service, error_message=str(e))



def get_bulk_export_data(user_service, task_id, is_initial_provider_sync):
    """
    Retrieve bulk export data for a user's resources.

    This function fetches URLs of bulk resource data for the specified user from the 
    1Up Health bulk data export API. It supports both initial and incremental 
    synchronization based on the user's last sync date.

    Steps:
        1. Constructs the API endpoint URL. If it's not the initial sync, appends the 
           `_since` parameter with the last synchronization date.
        2. Updates the user's `ongoing_sync_date` to the current time.
        3. Sends a request to fetch bulk resource data.
        4. Validates and processes the API response:
            - Extracts resource types and their URLs.
            - Logs sync details via `add_datasynclog_entry`.
            - Processes each resource using `process_1up_data`.
        5. Handles and logs exceptions, updates the user's sync status to 'failed', 
           and sends a socket message to notify the user of the failure.

    Args:
        user_service (UserServiceToken): The user service instance associated with the sync process.
        task_id (str): The unique identifier for the synchronization task.
        is_initial_provider_sync (bool): Indicates if this is the initial synchronization 
                                         for the provider.

    Returns:
        int: Always returns 1, signifying the process has been executed (successfully or failed).

    """

    try:
        url = BULK_DATA_EXPORT_URL

        if user_service.initial_sync :
            last_sync_date = user_service.last_sync_date
            formated_last_sync_date = last_sync_date.strftime('%Y-%m-%dT%H:%M:%S')
            url = BULK_DATA_EXPORT_URL+'&_since='+formated_last_sync_date

        user_service.ongoing_sync_date = timezone.now()
        user_service.save()

        response = fetch_api_data(user_service, task_id, url, is_initial_provider_sync)
        data = response.json()
        
        types = [item.get('type') for item in data.get('output')]
        if not types:
            raise Exception("No data found")
        print('types :: ',types)
        
        add_datasynclog_entry(data, user_service, task_id)

        for item in data['output']:
            item_url = item['url']
            item_type = item['type']
            process_1up_data(item_type, item_url, user_service, task_id, is_initial_provider_sync)
    except Exception as e:
        log_failure(task_id, user_service, error_message="inside get_bulk_export_data function : "+str(e))
        message = str(user_service.service.name)+ "sync failed"
        user_service.sync_status = 'failed'
        user_service.save()

        send_socket_message(user_service.user.id, message, user_service.id)

    return 1

def add_datasynclog_entry(data, user_service, task_id):
    """
    Add an entry to the DataSyncLog for tracking resource synchronization.

    This function processes the provided data and logs synchronization events 
    for various resource types. It checks if a log entry already exists for the 
    specified user service and task, and either increments the page count or 
    creates a new log entry depending on the state of the synchronization.
    
    Args:
        data (dict): A dictionary containing the data of bulk api response. Expected to 
                    have an 'output' key, which contains a list of resource items.
        user_service (UserServiceToken): The user service object for which the sync log 
                                        entry is being created.
        task_id (str): The unique identifier for the synchronization task.

    Returns:
        None: The function doesn't return a value. It updates the `DataSyncLog` 
            entries in the database.
    """

    RESOURCE_TYPE_CHOICES = {
                    'Condition': 'condition',
                    'Encounter': 'encounter',
                    'MedicationRequest': 'prescription',
                    'DocumentReference': 'document',
                    'CarePlan': 'careplan',
                    'AllergyIntolerance': 'allergyintolerence',
                }
    for item in data['output']:
        resource_type = RESOURCE_TYPE_CHOICES.get(item['type'])
        if resource_type:

            log_entry = DataSyncLog.objects.filter(
                resource=resource_type,
                user_service_id=user_service.id,
                task_id=task_id,
                is_complete=False,
                status='processing'
            ).first()

            if log_entry:
                # If the log entry exists, increment the total_page_count and save
                log_entry.total_page_count += 1
                log_entry.save()

            else:
                sync_type = 'refresh' if user_service.initial_sync else 'initial'
                # If no existing log entry is found, create a new one
                log_entry = DataSyncLog.objects.create(
                    resource=resource_type,
                    user_service_id=user_service.id,
                    user=user_service.user.id,
                    task_id=task_id,
                    sync_type=sync_type,
                    total_page_count=1 
                )


def  process_1up_data(type, item_url, user_service, task_id, is_initial_provider_sync):
    """
    Processes data for a specified resource type using dynamically selected processing functions.

    Args:
        type (str): The resource type to process (e.g., 'Condition', 'DocumentReference', etc.).
        item_url (str): The URL of the item to process.
        user_service (UserService): The user service object associated with the current user.
        task_id (str): The unique identifier for the synchronization task.
        is_initial_provider_sync (bool): Indicates whether the processing is part of an initial provider synchronization.

    Returns:
        int: returns `1` .
    """
     
    print("inside process_1up_data")
    processing_functions = {
        'Condition': process_condition_data,
        'DocumentReference': process_document_reference_data,
        'Encounter': process_encounter_data,
        'MedicationRequest': process_medication_request_data
    }
    
    process_func = processing_functions.get(type)

    if process_func:
        # Call the processing function with delay if it's a Celery task
        if hasattr(process_func, 'delay'):
            process_func.delay(item_url, user_service.id, task_id, is_initial_provider_sync)
    else:
        log_failure(task_id, user_service, error_message=f"No processing function found for type: {type}")
    
    return 1


def load_encounter_data(user_service, task_id, lst_data, main_task_id, is_initial_provider_sync):
    """
    Processes and synchronizes encounter data by creating or updating records in the database.

    - Extracts and processes encounter data from `lst_data` to either create or update records in the database.
    - Starts a separate thread to save bulk export data for encounters asynchronously.
    - Performs bulk insert (`bulk_create`) for new encounters and bulk update (`bulk_update`) for existing ones.
    - Tracks the synchronization status, including newly created, updated, and failed records.
    - Logs detailed information for success and failure cases using `log_failure` and `update_data_sync_log`.

    Args:
        user_service (UserServiceToken): The user service object associated with the current user.
        task_id (str): The task ID for tracking the specific sub-task.
        lst_data (list): List of encounter data dictionaries fetched from an external source.
        main_task_id (str): The main task ID to group related sub-tasks for logging purposes.
        is_initial_provider_sync (bool): Indicates whether the processing is part of an initial provider synchronization.

    Returns:
        bool: returns `True` 
    """

    error_message = ""
    status = "failed"
    sync_data = {}
    no_of_records = 0

    try:
        # Initialize data holders
        encounter_details = []
        updated_encounters = []

        lst_created_ref_num = []
        lst_updated_ref_num = []
        lst_failed_entries = []


        encounter_ids = [encounter.get('id') for encounter in lst_data]
        no_of_records = len(lst_data)

        # Fetch existing encounters based on encounter IDs
        existing_encounters = Encounter.objects.filter(ref_num__in=encounter_ids, user=user_service.user).only('ref_num')
        existing_encounters_map = {enc.ref_num: enc for enc in existing_encounters}

        # Start a new thread to save EncounterBulkExport data in the background
        encounter_thread = threading.Thread(target=save_encounter_bulk_export, args=(lst_data, encounter_ids, user_service))
        encounter_thread.start()

        # Iterate over encounter data
        for encounter in lst_data:
            try:
                # Extract fields
                ref_num = encounter.get('id')
                hospital = encounter.get('serviceProvider', {}).get('display')
                condition = encounter.get('reasonCode')[0].get('text') if encounter.get('reasonCode') else None
                last_synced = encounter.get('meta', {}).get('lastUpdated')
                practitioner = (
                    encounter.get('participant', [])[0].get('individual', {}).get('display') 
                    if encounter.get('participant') else None
                )
                period_end = encounter.get('period', {}).get('start')

                # Convert period_end to datetime object
                period_end_dt = datetime.strptime(period_end, '%Y-%m-%dT%H:%M:%S.%fZ') if period_end else None
                last_synced_dt = datetime.strptime(last_synced, '%Y-%m-%dT%H:%M:%S.%fZ') if last_synced else None

                if period_end_dt:
                    period_end_dt = timezone.make_aware(period_end_dt, timezone=timezone.utc)

                if last_synced_dt:
                    last_synced_dt = timezone.make_aware(last_synced_dt, timezone=timezone.utc)

                # Check if encounter already exists
                existing_encounter = existing_encounters_map.get(ref_num)

                if existing_encounter:
                    # Update existing encounter
                    existing_encounter.facility = hospital
                    existing_encounter.condition = condition
                    existing_encounter.physician = practitioner
                    existing_encounter.date_of_record = period_end_dt
                    existing_encounter.encounter_date = period_end_dt
                    existing_encounter.record_synced_at = last_synced_dt
                    updated_encounters.append(existing_encounter)

                    lst_updated_ref_num.append(existing_encounter.ref_num)
                else:
                    # Add new encounter to the list
                    encounter_details.append(
                        Encounter(
                            ref_num=ref_num,
                            condition=condition,
                            facility=hospital,
                            physician=practitioner,
                            date_of_record=period_end_dt,
                            encounter_date=period_end_dt,
                            record_synced_at=last_synced,
                            user=user_service.user
                        )
                    )
                    lst_created_ref_num.append(ref_num)
            except Exception as e:
                lst_failed_entries.append({
                    "ref_num" :encounter.get('id'),
                    "reason" : str(e)
                })

        # Perform bulk operations
        if encounter_details:
            try:
                Encounter.objects.bulk_create(encounter_details)     
            except Exception as e:
                log_failure(main_task_id, user_service, error_message=f"sub_task:{task_id}, encounter create : {str(e)}")


        if updated_encounters:
            try:
                Encounter.objects.bulk_update(
                    updated_encounters,
                    ['facility', 'condition', 'physician', 'date_of_record', 'encounter_date', 'record_synced_at']
                )
            except Exception as e:
                log_failure(main_task_id, user_service, error_message=f"sub_task:{task_id},encounter update  : {str(e)}")

        # Log data sync
        sync_data = {
            "created_ref_num":lst_created_ref_num,
            "updated_ref_num":lst_updated_ref_num,
            "failed_entries" :lst_failed_entries
            }
        status = "completed"

    except Exception as e:
        # Log error details
        error_message = str(e)
        log_failure(main_task_id, user_service, error_message=f"sub_task:{task_id}, encounter error: {error_message}")

    update_data_sync_log(user_service, 'encounter', no_of_records, main_task_id, sync_data, status, error_msg=error_message)

    return True
  


def load_medication_request_data(user_service, task_id, lst_data, main_task_id, is_initial_provider_sync):
    """
    Processes and synchronizes medication request data by creating or updating records in the database.

    - Extracts and processes medication request data from `lst_data` to either create or update records in the database.
    - Starts a separate thread to save bulk export data for medication requests asynchronously.
    - Performs bulk insert (`bulk_create`) for new medication requests and bulk update (`bulk_update`) for existing ones.
    - Tracks the synchronization status, including newly created, updated, and failed records.
    - Logs detailed information for success and failure cases using `log_failure` and `update_data_sync_log`.

    Args:
        user_service (UserServiceToken): The user service object associated with the current user.
        task_id (str): The task ID for tracking the specific sub-task.
        lst_data (list): List of medication request data dictionaries fetched from an external source.
        main_task_id (str): The main task ID to group related sub-tasks for logging purposes.
        is_initial_provider_sync (bool): Indicates whether the processing is part of an initial provider synchronization.

    Returns:
        bool: returns `True` 
    """
    error_message = ""
    status = "failed"
    sync_data = {}
    no_of_records = 0

    try:
        # Fetch existing prescriptions and encounters
        ref_nums = [mr.get('id') for mr in lst_data]
        existing_prescriptions = Prescription.objects.filter(ref_num__in=ref_nums, user=user_service.user).only('ref_num')
        existing_prescriptions_map = {p.ref_num: p for p in existing_prescriptions}
        
        encounter_ref_nums = [
            mr.get('encounter', {}).get('reference', "").split('/')[1]
            for mr in lst_data if mr.get('encounter')
        ]
        encounters = Encounter.objects.filter(ref_num__in=encounter_ref_nums, user=user_service.user).only('ref_num')
        encounters_map = {e.ref_num: e for e in encounters}
        
        # Initialize data holders
        new_medication_details = []
        updated_prescriptions = []
        lst_created_ref_num = []
        lst_updated_ref_num = []
        lst_failed_entries = []
        no_of_records = len(lst_data)

        medication_request_thread = threading.Thread(target=save_medication_request_bulk_export, args=(lst_data, ref_nums, user_service))
        medication_request_thread.start()

        # Iterate over medication requests
        for medication_request in lst_data:
            try:
                ref_num = medication_request.get('id')
                encounter_ref = medication_request.get('encounter', {}).get('reference', "")
                encounter = encounters_map.get(encounter_ref.split('/')[1]) if encounter_ref else None

                # Extract common fields
                active_substance = medication_request.get('medicationCodeableConcept', {}).get('text')
                prescribed_by = medication_request.get('requester', {}).get('display')

                prescription_expiry_date = medication_request.get('dispenseRequest', {}).get('validityPeriod', {}).get('end')
                prescription_expiry = None
                if prescription_expiry_date:
                    try:
                        prescription_expiry = datetime.strptime(prescription_expiry_date, '%Y-%m-%dT%H:%M:%S.%fZ').date()
                    except ValueError:
                        prescription_expiry = datetime.strptime(prescription_expiry_date, '%Y-%m-%d').date()
                directions = ' '.join([di.get('patientInstruction', "") for di in medication_request.get('dosageInstruction', [])])
                last_synced = medication_request.get('meta', {}).get('lastUpdated', None)

                prescription_obj = existing_prescriptions_map.get(ref_num)
                if prescription_obj:
                    # Update existing prescription
                    prescription_obj.active_substance = active_substance
                    prescription_obj.encounter = encounter
                    prescription_obj.prescribed_by = prescribed_by
                    prescription_obj.prescription_expiry = prescription_expiry
                    prescription_obj.directions = directions
                    prescription_obj.record_synced_at = last_synced
                    updated_prescriptions.append(prescription_obj)
                    lst_updated_ref_num.append(prescription_obj.ref_num)
                else:
                    # Create new prescription entry
                    new_medication_details.append(
                        Prescription(
                            ref_num=ref_num,
                            active_substance=active_substance,
                            encounter=encounter,
                            prescribed_by=prescribed_by,
                            prescription_expiry=prescription_expiry,
                            directions=directions,
                            user=user_service.user,
                            record_synced_at=last_synced
                        )
                    )
                    lst_created_ref_num.append(ref_num)

            except Exception as e:
                lst_failed_entries.append({
                    "ref_num" :medication_request.get('id'),
                    "reason" : str(e)
                })

        #  Perform bulk operations
        if new_medication_details:
            try:
                Prescription.objects.bulk_create(new_medication_details)
            except Exception as e:
                log_failure(main_task_id, user_service, error_message=f"sub_task:{task_id}, prescription create : {str(e)}")
        if updated_prescriptions:
            try:
                Prescription.objects.bulk_update(updated_prescriptions, ['active_substance', 'encounter', 'prescribed_by', 'prescription_expiry', 'directions', 'record_synced_at'])
            except Exception as e:
                log_failure(main_task_id, user_service, error_message=f"sub_task:{task_id},prescription update : {str(e)}")
        
        # Step 5: Log data sync
        sync_data = {
            "created_ref_num":lst_created_ref_num,
            "updated_ref_num":lst_updated_ref_num,
            "failed_entries" :lst_failed_entries
        }
        status = "completed"
        
    except Exception as e:
        # Log error details
        error_message = str(e)
        log_failure(main_task_id, user_service, error_message=f"sub_task:{task_id}, prescription error: {error_message}")
        
    update_data_sync_log(user_service, 'prescription', no_of_records, main_task_id, sync_data, status, error_msg=error_message)

    return True   
           

def load_condition_data(user_service, task_id, lst_data, main_task_id, is_initial_provider_sync):
    """
    Processes and synchronizes condition data by creating or updating records in the database.

    - Extracts and processes condition data from `lst_data` to either create or update records in the database.
    - Starts a separate thread to save bulk export data for conditions asynchronously.
    - Performs bulk insert (`bulk_create`) for new conditions and bulk update (`bulk_update`) for existing ones.
    - Tracks the synchronization status, including newly created, updated, and failed records.
    - Logs detailed information for success and failure cases using `log_failure` and `update_data_sync_log`.

    Args:
        user_service (UserServiceToken): The user service object associated with the current user.
        task_id (str): The task ID for tracking the specific sub-task.
        lst_data (list): List of condition data dictionaries fetched from an external source.
        main_task_id (str): The main task ID to group related sub-tasks for logging purposes.
        is_initial_provider_sync (bool): Indicates whether the processing is part of an initial provider synchronization.

    Returns:
        bool: returns `True` 
    """

    error_message = ""
    status = "failed"
    sync_data = {}
    no_of_records = 0

    try:
        # Step 1: Initialize data holders
        condition_details = []
        updated_conditions = []

        lst_created_ref_num = []
        lst_updated_ref_num = []
        lst_failed_entries = []
        condition_ids = [condition.get('id') for condition in lst_data]
        no_of_records = len(lst_data)

        # Step 2: Fetch existing conditions based on condition IDs
        existing_conditions = Condition.objects.filter(ref_num__in=condition_ids, user=user_service.user).only('ref_num')
        existing_conditions_map = {cond.ref_num: cond for cond in existing_conditions}

        encounter_ref_nums = [
            mr.get('encounter', {}).get('reference', "").split('/')[1]
            for mr in lst_data if mr.get('encounter')
        ]
        encounters = Encounter.objects.filter(ref_num__in=encounter_ref_nums).only('ref_num')
        encounters_map = {e.ref_num: e for e in encounters}

        condition_thread = threading.Thread(target=save_condition_bulk_export, args=(lst_data, condition_ids, user_service))
        condition_thread.start()

        # Step 3: Iterate over condition data
        for condition in lst_data:
            try:
                # Extract fields
                ref_num = condition.get('id')
                last_synced = condition.get('meta', {}).get('lastUpdated')
                encounter = None

                encounter_ref = condition.get('encounter', {}).get('reference', "")
                encounter = encounters_map.get(encounter_ref.split('/')[1]) if encounter_ref else None

                code_text = condition.get('code', {}).get('text')
                code_value = None
                if 'coding' in condition.get('code', {}):
                    for coding_item in condition['code']['coding']:
                        code_value = coding_item.get('code')
                        if code_value:
                            break

                # Check if condition already exists
                existing_condition = existing_conditions_map.get(ref_num)

                if existing_condition:
                    # Update existing condition
                    existing_condition.health_indicator = code_text
                    existing_condition.diagnosis_code = code_value
                    existing_condition.encounter = encounter
                    existing_condition.record_synced_at = last_synced
                    updated_conditions.append(existing_condition)

                    lst_updated_ref_num.append(existing_condition.ref_num)

                else:
                    # Add new condition to the list
                    condition_details.append(
                        Condition(
                            ref_num=ref_num,
                            health_indicator=code_text,
                            diagnosis_code=code_value,
                            encounter=encounter,
                            record_synced_at=last_synced,
                            user=user_service.user
                        )
                    )
                    lst_created_ref_num.append(ref_num)

            except Exception as e:
                lst_failed_entries.append({
                    "ref_num" : condition.get('id'),
                    "reason" : str(e)
                })

        # Step 4: Perform bulk operations
        if condition_details:
            try:
                Condition.objects.bulk_create(condition_details)
            except Exception as e:
                log_failure(main_task_id, user_service, error_message=f"sub_task:{task_id},condition create : {str(e)}")
        if updated_conditions:
            try:
                Condition.objects.bulk_update(
                    updated_conditions,
                    ['health_indicator', 'diagnosis_code', 'encounter', 'record_synced_at']
                )
            except Exception as e:
                log_failure(main_task_id, user_service, error_message=f"sub_task:{task_id},condition update : {str(e)}")

        sync_data = {
            "created_ref_num":lst_created_ref_num,
            "updated_ref_num":lst_updated_ref_num,
            "failed_entries" :lst_failed_entries
        }
        status = "completed"

    except Exception as e:
        # Log error details
        error_message = str(e)
        log_failure(main_task_id, user_service, error_message=f"sub_task:{task_id}, condition error: {error_message}")
        
    update_data_sync_log(user_service, 'condition', no_of_records, main_task_id, sync_data, status, error_msg=error_message)
    return True


def load_document_reference_data(user_service, task_id, lst_data, main_task_id, is_initial_provider_sync):
    """
    Synchronizes and processes document reference data by fetching, decoding, and storing document details.

    This function handles the creation and updating of document records in bulk. It fetches file content from a given 
    URL, decodes it from base64, and saves it as a file object associated with a document. The function also logs 
    successes and failures for auditing purposes and updates a data synchronization log upon completion.

    - Extracts document details, including title, type, content type, and file data, from `lst_data`.
    - Fetch file data using URLs provided in the documents and decodes it from Base64 format.
    - Checks if a document with the same `ref_num` exists in the database:
        - Updates fields if the document exists.
        - Creates a new record if the document does not exist.
    - Background thread to save bulk export data for documents asynchronously.
    - Performs the following:
        - Logs success or failure details for each document.
        - Maintains lists for created, updated, and failed document reference numbers.

    Args:
        user_service (UserServiceToken): The user service object associated with the current user.
        task_id (str): The task ID for tracking the specific sub-task.
        lst_data (list): List of document reference data dictionaries fetched from an external source.
        main_task_id (str): The main task ID to group related sub-tasks for logging purposes.
        is_initial_provider_sync (bool): Indicates whether the processing is part of an initial provider synchronization.

    Returns:
        bool: returns `True`

    """

    error_message = ""
    status = "failed"
    sync_data = {}
    no_of_records = 0
    try:
        # Initialize
        no_of_records = len(lst_data)
        content_type_mapping = {
            'text/plain': 'txt',
            'text/html': 'html',
            'text/xml': 'xml',
            'application/pdf': 'pdf',
            'image/jpeg': 'jpg',
            'image/png': 'png',
            'image/gif': 'gif',
            'application/dicom': 'dcm'
        }

        # Lists to hold records for bulk operations
        documents_to_create = []

        lst_created_ref_num = []
        lst_updated_ref_num = []
        lst_failed_entries = []

        document_ids = [document.get('id') for document in lst_data]

        # Fetch existing conditions based on condition IDs
        existing_documents = Document.objects.filter(ref_num__in=document_ids, user=user_service.user).only('ref_num')
        existing_documents_map = {cond.ref_num: cond for cond in existing_documents}

        document_reference_thread = threading.Thread(target=save_document_reference_bulk_export, args=(lst_data, document_ids, user_service))
        document_reference_thread.start()
        # Iterate through document reference data

        for document in lst_data:


            text = document.get('type', {}).get('text')
            try:
                # Extract attachment details
                attachment = document['content'][0]['attachment']
                title = attachment.get('title')
                content_type = attachment.get('contentType')
                url = attachment['url']
                ref_num = document['id']

                # Fetch file data from the URL
                response = fetch_api_data(user_service, task_id, url, is_initial_provider_sync)
                try:
                    result = response.json()
                except Exception as err:
                    lst_failed_entries.append({
                        "ref_num" : document.get('id'),
                        "reason" : str(err)
                    })

                base64_string = result.get('data')
                # Decode base64 file content
                if base64_string:
                    file_data = base64.b64decode(base64_string)
                    # Generate a unique filename based on content type
                    file_extension = content_type_mapping.get(content_type, 'bin')  # Default to 'bin' if not mapped
                    filename = f"{text}.{file_extension}"
                    # Create file object for document
                    document_file = ContentFile(file_data, filename)
                    
                    # Check if document with the same ref_num exists
                    existing_document = existing_documents_map.get(ref_num)
                    if existing_document:
                        # If document exists, update its fields
                        existing_document.files = document_file
                        existing_document.title = text
                        existing_document.notes = title
                        existing_document.user = user_service.user
                        try:
                            existing_document.save()
                            lst_updated_ref_num.append(existing_document.ref_num)
                        except Exception as e:
                            log_failure(main_task_id, user_service, error_message=f"sub_task:{task_id}, Document {ref_num} update failed: {str(e)}")
                            lst_failed_entries.append({
                                "ref_num" : document.get('id'),
                                "reason" : str(e)
                            })

                    else:
                        Document.objects.create(
                            files=document_file,
                            file_name=filename,     
                            title=text,            
                            notes=title,            
                            user=user_service.user, 
                            ref_num=ref_num 
                        )
                        lst_created_ref_num.append(ref_num)


            except Exception as e:
                # Log attachment details and error
                log_failure(main_task_id, user_service, error_message=f"sub_task:{task_id}, Error processing document {document.get('id')}: {str(e)}")
                lst_failed_entries.append({
                    "ref_num" : document.get('id'),
                    "reason" : str(e)
                })

        sync_data = {
            "created_ref_num":lst_created_ref_num,
            "updated_ref_num":lst_updated_ref_num,
            "failed_entries" :lst_failed_entries
        }

        status = "completed"

    except Exception as e:
        # Log error
        error_message = str(e)
        log_failure(main_task_id, user_service, error_message=f"sub_task:{task_id}, document error: {error_message}")

    update_data_sync_log(user_service, 'document', no_of_records, main_task_id, sync_data, status, error_msg=error_message)

    
    return True



def update_data_sync_log(user_service, resource, no_of_records, main_task_id, sync_data, status, error_msg):
    """
    Updates the data synchronization log for tracking progress and status of resource synchronization tasks.

    This function updates or creates log entries for a given resource synchronization task. It tracks completed pages, 
    total records processed, and synchronization outcomes such as created, updated, and failed entries. Additionally, 
    it checks whether all logs for the given task are complete and triggers a completion update if necessary.

    Args:
        user_service (object): The user service object representing the user initiating the synchronization task.
        resource (str): The resource type being synchronized (e.g., 'document', 'condition').
        no_of_records (int): The number of records processed in the current operation.
        main_task_id (str): The unique identifier of the main task for grouping related log entries.
        sync_data (dict): A dictionary containing synchronization details:
                          - `created_ref_num`: List of successfully created references.
                          - `updated_ref_num`: List of successfully updated references.
                          - `failed_entries`: List of failed entries with reasons.
        status (str): The current status of the synchronization task (e.g., 'completed', 'failed').
        error_msg (str): Any error message encountered during the operation.

    Returns:
        None

    Functionality:
        1. Fetches the existing log entry for the given user, resource, and task ID.
        2. Updates the following:
            - `completed_page_count` and `no_of_records` fields.
            - The `payload` JSON field to include created, updated, and failed entries.
            - The `error_msg` field for logging issues encountered.
        3. Marks the log as complete if all pages are processed.
        4. Triggers a global completion check for all logs associated with the task.
        5. Sends a process completion update if all logs for the task are complete.

    """
    try:
        log_entry = DataSyncLog.objects.filter(
            user_service_id=user_service.id, resource=resource, task_id=main_task_id
        ).first()

        if log_entry:
            # Update the counters
            log_entry.completed_page_count = F('completed_page_count') + 1
            log_entry.no_of_records = F('no_of_records') + no_of_records

            # Update the payload field (assumed to be a JSON field)
            existing_payload = log_entry.payload or {}  # Get current payload or empty if None

            # Append or update the JSON data
            existing_payload['created_ref_num'] = existing_payload.get('created_ref_num', []) + sync_data.get('created_ref_num', [])
            existing_payload['updated_ref_num'] = existing_payload.get('updated_ref_num', []) + sync_data.get('updated_ref_num', [])
            existing_payload['failed_entries'] = existing_payload.get('failed_entries', []) + sync_data.get('failed_entries', [])


            # Assign the updated payload back to the log entry
            log_entry.payload = existing_payload
            log_entry.error_msg = error_msg
            # Save the updated log entry
            log_entry.save()


        # Check if completed_page_count equals total_page_count and set is_complete to True
        DataSyncLog.objects.filter(
            user_service_id=user_service.id, 
            resource=resource,
            task_id=main_task_id,
            completed_page_count=F('total_page_count')
        ).update(is_complete=True, status=status)

        # Check if all DataSyncLogs for this user_service_id are complete
        all_logs_complete = not DataSyncLog.objects.filter(user_service_id=user_service.id, task_id=main_task_id).exclude(is_complete=True).exists()

        if all_logs_complete:
            # Trigger the process completion update if all logs are complete
            send_process_completion_update(user_service)
    except Exception as e:
        log_failure(main_task_id, user_service, error_message=f"Error in DataSyncLog: {str(e)}")


def send_process_completion_update(user_service):
    """
    Updates the synchronization status of a user service upon completion, 
    saves the relevant fields, and sends a socket message to notify the user 
    about the completion of the sync process.

    Args:
        user_service (UserServiceToken): The user service instance for which the sync completion update is being processed. 
            It should contain the user's service details, sync status, and related timestamps.

    Returns:
        bool: True
    """

    print("inside complete ")

    message = str(user_service.service.name)+ "sync completed"

    group = user_service.user.id
    user_service_id = user_service.id

    if not user_service.initial_sync:
        user_service.initial_sync = True

    user_service.last_sync_date = user_service.ongoing_sync_date
    user_service.sync_status = 'completed'
    user_service.save()

    send_socket_message(group, message, user_service_id)
    return True


def send_socket_message(group, message, user_service_id):
    """
    Sends a notification message to the backend via an HTTP GET request to the specified API.
    If the request fails, logs the error with relevant details in the `DataSyncExceptionLog` model.

    Args:
        group (int): The ID of the user or group to which the notification is sent.
        message (str): The message to be sent in the notification.
        user_service_id (int): The ID of the user service.

    Returns:
        bool: True
    """

    params = {
        'group': group,
        'message': message,
        'response_type': 'data_sync',
        'user_service_id': user_service_id
    }
    try:
        # Send the GET request with query parameters
        response = requests.get(BEEK_NOTIFICATION_API, params=params)

        if response.status_code != 200:
            DataSyncExceptionLog.objects.create(
                task_id="NA",
                payload={
                    "user_id": str(group),
                    "service_id": str(user_service_id),
                    "error": f"Failed to notify backend: {response.text}"
                }
            )
        print("Notification sent successfully.", message)
        
    except Exception as e:
        DataSyncExceptionLog.objects.create(
            task_id="NA",
            payload={
                "user_id": str(group),
                "service_id": str(user_service_id),
                "error": f"Failed to notify backend: {str(e)}"
            }
        )
    
        return True
