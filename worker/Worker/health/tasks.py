import requests
from celery import shared_task
from health.models import UserServiceToken
import json
from decouple import config

AWS_SQS_CONDITION_QUEUE = config('AWS_SQS_CONDITION_QUEUE')
AWS_SQS_ENCOUNTER_QUEUE = config('AWS_SQS_ENCOUNTER_QUEUE')
AWS_SQS_MEDICATION_REQUEST_QUEUE = config('AWS_SQS_MEDICATION_REQUEST_QUEUE')
AWS_SQS_DOCUMENT_REFERENCE_QUEUE = config('AWS_SQS_DOCUMENT_REFERENCE_QUEUE')

def convert_to_json(response):
    """
    Converts an NDJSON (Newline Delimited JSON) response object into a list of JSON objects.

    This function processes the NDJSON response, where each line is a valid JSON object,
    and decodes each line into a corresponding Python dictionary. If decoding fails for any line,
    the error is logged, and an empty list is returned.

    Args:
        response (Response): A response object (typically from an HTTP request) that contains NDJSON data. 
                              The response should be iterable, with each line representing a valid JSON object.

    Returns:
        list: A list of JSON objects (Python dictionaries) parsed from the NDJSON response. 
              If there is a JSON decoding error, an empty list is returned.

    """

    try:
        json_list = []
        for line in response.iter_lines():
            if line:
                json_object = json.loads(line.decode('utf-8'))
                json_list.append(json_object)

        return json_list

    except json.JSONDecodeError as e:
        print(f"Failed to decode JSON: {str(e)}")
        return []
    

def get_user_service_token(user_service_id):
    """
    Helper function to get the UserServiceToken object by ID.
    """
    try:
        return UserServiceToken.objects.get(id=user_service_id)
    except UserServiceToken.DoesNotExist:
        print(f"UserServiceToken with ID {user_service_id} does not exist.")
        return None


def process_task(item_url, user_service_id, data_loader, main_task_id, sub_task_id, is_initial_provider_sync):
    """
    Processes a task by fetching data from an API and loading it using the provided data loader function.

    This function retrieves an API token for the user service, fetches the required data from the 
    specified URL using the `fetch_api_data` function, converts the response to a list of JSON objects, 
    and then processes the data using the provided `data_loader` function. If an error occurs during 
    data loading, it is caught and logged.

        - Retrieves the user service token using `get_user_service_token`.
        - Fetches the data using `fetch_api_data`.
        - Converts the response data into JSON objects.
        - Loads the data using the provided `data_loader` function.

    Args:
        item_url (str): The URL to fetch the data from.
        user_service_id (int): The ID of the user service used to retrieve the API token.
        data_loader (function): A function responsible for loading the fetched data into the system.
        main_task_id (str): The ID of the main task to which this sub-task belongs.
        sub_task_id (str): The ID of the specific sub-task being processed.
        is_initial_provider_sync (bool): Flag indicating whether the sync is the initial sync for the provider.

    Returns:
        None: This function doesn't return any value. It performs the task of fetching and loading the data.
    """

    user_service = get_user_service_token(user_service_id)
    from health.views import fetch_api_data
    item_response = fetch_api_data(user_service, sub_task_id, item_url, is_initial_provider_sync)
    lst_data = convert_to_json(item_response)
    
    if user_service:
        try:
            data_loader(user_service, sub_task_id, lst_data, main_task_id, is_initial_provider_sync)
        except Exception as e:
            print("Error processing data:", str(e))


@shared_task(name='process_condition_data', queue=AWS_SQS_CONDITION_QUEUE)
def process_condition_data(item_url, user_service_id, main_task_id, is_initial_provider_sync):
    """
    Process condition data by fetching and loading it into the system.

    This task is responsible for processing condition data from a given URL and
    loading it into the system using the provided `load_condition_data` function.

    Args:
        item_url (str): The URL to fetch the condition data from.
        user_service_id (str): The ID of the UserServiceToken.
        main_task_id (str): The main celery task ID.
        is_initial_provider_sync (bool): A flag indicating whether this is an initial sync for the provider.

    Queue:
        This task is executed in the AWS SQS queue specified by the `AWS_SQS_CONDITION_QUEUE` configuration.

    Returns:
        int: returns 1 after task completion.
    """

    from health.views import load_condition_data
    sub_task_id = process_condition_data.request.id 
    print("Processing condition data task")
    process_task(item_url, user_service_id, load_condition_data, main_task_id, sub_task_id, is_initial_provider_sync)
    return 1


@shared_task(name='process_encounter_data', queue=AWS_SQS_ENCOUNTER_QUEUE)
def process_encounter_data(item_url, user_service_id, main_task_id, is_initial_provider_sync):
    """
    Process encounter data by fetching and loading it into the system.

    This task is responsible for processing encounter data from a given URL and
    loading it into the system using the provided `load_encounter_data` function.

    Args:
        item_url (str): The URL to fetch the encounter data from.
        user_service_id (str): The ID of the UserServiceToken.
        main_task_id (str): The main celery task ID.
        is_initial_provider_sync (bool): A flag indicating whether this is an initial sync for the provider.

    Queue:
        This task is executed in the AWS SQS queue specified by the `AWS_SQS_ENCOUNTER_QUEUE` configuration.

    Returns:
        int: returns 1 after task completion.
    """

    from health.views import load_encounter_data
    sub_task_id = process_encounter_data.request.id 
    print("Processing encounter data task")
    process_task(item_url, user_service_id, load_encounter_data,main_task_id,  sub_task_id, is_initial_provider_sync)
    return 1

@shared_task(name='process_medication_request_data', queue=AWS_SQS_MEDICATION_REQUEST_QUEUE)
def process_medication_request_data(item_url, user_service_id, main_task_id, is_initial_provider_sync):
    """
    Process medication request data by fetching and loading it into the system.

    This task is responsible for processing medication request data from a given URL and
    loading it into the system using the provided `load_medication_request_data` function.

    Args:
        item_url (str): The URL to fetch the medication request data from.
        user_service_id (str): The ID of the UserServiceToken.
        main_task_id (str): The main celery task ID.
        is_initial_provider_sync (bool): A flag indicating whether this is an initial sync for the provider.

    Queue:
        This task is executed in the AWS SQS queue specified by the `AWS_SQS_MEDICATION_REQUEST_QUEUE` configuration.

    Returns:
        int: returns 1 after task completion.
    """

    from health.views import load_medication_request_data
    sub_task_id = process_medication_request_data.request.id
    print("Processing medication request data task")
    process_task(item_url, user_service_id, load_medication_request_data, main_task_id, sub_task_id, is_initial_provider_sync)
    return 1


@shared_task(name='process_document_reference_data', queue=AWS_SQS_DOCUMENT_REFERENCE_QUEUE)
def process_document_reference_data(item_url, user_service_id, main_task_id, is_initial_provider_sync):
    """
    Process document reference data by fetching and loading it into the system.

    This task is responsible for processing document reference data from a given URL and
    loading it into the system using the provided `load_document_reference_data` function.

    Args:
        item_url (str): The URL to fetch the document reference data from.
        user_service_id (str): The ID of the UserServiceToken.
        main_task_id (str): The main celery task ID.
        is_initial_provider_sync (bool): A flag indicating whether this is an initial sync for the provider.

    Queue:
        This task is executed in the AWS SQS queue specified by the `AWS_SQS_DOCUMENT_REFERENCE_QUEUE` configuration.

    Returns:
        int: returns 1 after task completion.
    """
     
    from health.views import load_document_reference_data
    sub_task_id = process_document_reference_data.request.id
    print("Processing Document Reference data task")
    process_task(item_url, user_service_id, load_document_reference_data, main_task_id, sub_task_id, is_initial_provider_sync)
    return 1