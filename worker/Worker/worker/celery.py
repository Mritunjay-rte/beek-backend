from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from decouple import config
from celery.exceptions import MaxRetriesExceededError
from celery.schedules import crontab
from django.utils.timezone import now
from datetime import timedelta

ACTIVATION_TOKEN_EXPIRY_HOURS = int(config('ACTIVATION_TOKEN_EXPIRY_HOURS'))
AWS_SQS_REGION = config('AWS_SQS_REGION')
AWS_SQS_ACCESS_KEY_ID = config('AWS_SQS_ACCESS_KEY_ID')
AWS_SQS_SECRET_ACCESS_KEY = config('AWS_SQS_SECRET_ACCESS_KEY')
AWS_SQS_QUEUE = config('AWS_SQS_QUEUE')
CELERY_RESULT_BACKEND = config('CELERY_RESULT_BACKEND')

AWS_SQS_GENERAL_URL = config('AWS_SQS_GENERAL_URL')
AWS_SQS_CONDITION_QUEUE = config('AWS_SQS_CONDITION_QUEUE')
AWS_SQS_ENCOUNTER_QUEUE = config('AWS_SQS_ENCOUNTER_QUEUE')
AWS_SQS_MEDICATION_REQUEST_QUEUE = config('AWS_SQS_MEDICATION_REQUEST_QUEUE')
AWS_SQS_DOCUMENT_REFERENCE_QUEUE = config('AWS_SQS_DOCUMENT_REFERENCE_QUEUE')

# Set the default Django settings module for the Celery application
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'worker.settings')

# Initialize the Celery application with the name 'worker'
app = Celery('worker')

# Load configuration from Django settings, prefixed with 'CELERY'
app.config_from_object('django.conf:settings', namespace='CELERY')

# Update Celery's configuration
app.conf.update(
    task_default_queue=AWS_SQS_QUEUE,
    broker_url='sqs://',
    broker_transport_options={
        'region': AWS_SQS_REGION,
        'predefined_queues': {
            AWS_SQS_QUEUE: {
                'url': AWS_SQS_GENERAL_URL+AWS_SQS_QUEUE,
                'access_key_id': AWS_SQS_ACCESS_KEY_ID,
                'secret_access_key': AWS_SQS_SECRET_ACCESS_KEY,
            },
            AWS_SQS_CONDITION_QUEUE : {
                'url': AWS_SQS_GENERAL_URL+AWS_SQS_CONDITION_QUEUE,
                'access_key_id': AWS_SQS_ACCESS_KEY_ID,
                'secret_access_key': AWS_SQS_SECRET_ACCESS_KEY,
            },
            AWS_SQS_ENCOUNTER_QUEUE : {
                'url': AWS_SQS_GENERAL_URL+AWS_SQS_ENCOUNTER_QUEUE,
                'access_key_id': AWS_SQS_ACCESS_KEY_ID,
                'secret_access_key': AWS_SQS_SECRET_ACCESS_KEY,
            },
            AWS_SQS_MEDICATION_REQUEST_QUEUE : {
                'url': AWS_SQS_GENERAL_URL+AWS_SQS_MEDICATION_REQUEST_QUEUE,
                'access_key_id': AWS_SQS_ACCESS_KEY_ID,
                'secret_access_key': AWS_SQS_SECRET_ACCESS_KEY,
            },
            AWS_SQS_DOCUMENT_REFERENCE_QUEUE : {
                'url': AWS_SQS_GENERAL_URL+AWS_SQS_DOCUMENT_REFERENCE_QUEUE,
                'access_key_id': AWS_SQS_ACCESS_KEY_ID,
                'secret_access_key': AWS_SQS_SECRET_ACCESS_KEY,
            },

        },
    },
    broker_connection_retry_on_startup=True,
    result_backend=CELERY_RESULT_BACKEND,
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json'
)
app.conf.task_protocol = 1
app.autodiscover_tasks()



@app.task(bind=True, acks_late=False, name='worker.process_sqs_message', max_retries=2)
def process_sqs_message(self, user_service_id, is_initial_provider_sync):
    """
    Process a message from the SQS queue and load user service data.

    This task processes an SQS message by fetching and loading user service data
    based on the provided `user_service_id`. It tracks the task ID for monitoring
    and supports retries in case of recoverable errors such as network issues.

    Args:
        self: Reference to the bound task instance, enabling task retries and metadata access.
        user_service_id (str): The ID of the user service data to be processed.
        is_initial_provider_sync (bool): A flag indicating whether this is the initial sync for the provider.

    Returns:
        bool: `True` if the task completes successfully.
    """

    from health.models import CeleryTaskmeta
    from health.views import load_user_service_data
    try:
        task_id = self.request.id
        print(f"Inside celery task {task_id}: {user_service_id}")
        print(f"is_initial_provider_sync : {type(is_initial_provider_sync)}")
                
        load_user_service_data(user_service_id, task_id, is_initial_provider_sync)
        
        
        return True

    except Exception as e:
        try:
            print("inside the process_sqs_message exception retry")
            # Retry task if it fails due to a network issue or other recoverable error
            self.retry(exc=e, countdown=min(2 ** self.request.retries, 60))  # Max 60 sec delay
            raise 
            
        except MaxRetriesExceededError as e:
            print("inside the MaxRetriesExceededError")
            error_message = str(e)
            print(f"Failed after {self.max_retries} retries.")
            CeleryTaskmeta.objects.filter(task_id=self.request.id).update(traceback=error_message)


@app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    """
    Configure periodic tasks for the Celery app.

    This function sets up a periodic task to delete expired user activation tokens.
    The task is scheduled to run daily at 12:30 AM using the Celery `crontab` scheduler.

    Args:
        sender: The sender of the signal, typically the Celery app instance.
        **kwargs: Additional keyword arguments passed by the signal.

    Periodic Tasks:
        - `delete_expired_tokens`: Deletes users with expired activation tokens.
          Scheduled to run at 12:30 AM every day.
    """

    sender.add_periodic_task(
        crontab(hour=0, minute=30),
        delete_expired_tokens.s(),
    )


@app.task()
def delete_expired_tokens():
    """
    Delete expired user activation tokens.

    This task identifies and deletes users with expired activation tokens. A user
    is considered for deletion if:
    - The activation token was created before the expiration threshold.
    - The activation token is not null.
    - The user's email is not verified.

    Expiration is determined based on the `ACTIVATION_TOKEN_EXPIRY_HOURS` setting.

    Returns:
        str: A message indicating the number of users deleted.

    """
    try:
        from user.models import User
        expiration_time = now() - timedelta(hours=ACTIVATION_TOKEN_EXPIRY_HOURS)
        expired_users = User.objects.filter(activation_token_created_on__lt=expiration_time, activation_token__isnull=False, is_email_verified=False)
        deleted_count = expired_users.count()
        expired_users.delete()
        return f"{deleted_count} expired users deleted"
    except Exception as e:
        print(str(e))