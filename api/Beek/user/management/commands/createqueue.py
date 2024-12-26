from django.core.management.base import BaseCommand
from botocore.exceptions import ClientError

from decouple import config
import boto3

AWS_SQS_REGION = config('AWS_SQS_REGION')
AWS_SQS_ACCESS_KEY_ID = config('AWS_SQS_ACCESS_KEY_ID')
AWS_SQS_SECRET_ACCESS_KEY = config('AWS_SQS_SECRET_ACCESS_KEY')

AWS_SQS_QUEUE = config('AWS_SQS_QUEUE')
AWS_SQS_CONDITION_QUEUE = config('AWS_SQS_CONDITION_QUEUE')
AWS_SQS_ENCOUNTER_QUEUE = config('AWS_SQS_ENCOUNTER_QUEUE')
AWS_SQS_MEDICATION_REQUEST_QUEUE = config('AWS_SQS_MEDICATION_REQUEST_QUEUE')
AWS_SQS_DOCUMENT_REFERENCE_QUEUE = config('AWS_SQS_DOCUMENT_REFERENCE_QUEUE')


class Command(BaseCommand):
    """
    Django management command to create Amazon SQS queues.

    This command ensures that a set of predefined SQS queues exist in the specified AWS region. 
    If a queue does not exist, it is automatically created. If the queue already exists, 
    its URL is retrieved and displayed.

    Queues handled:
    - AWS_SQS_QUEUE
    - AWS_SQS_CONDITION_QUEUE
    - AWS_SQS_ENCOUNTER_QUEUE
    - AWS_SQS_MEDICATION_REQUEST_QUEUE
    - AWS_SQS_DOCUMENT_REFERENCE_QUEUE

    AWS credentials and region are fetched from environment variables:
    - AWS_SQS_REGION
    - AWS_SQS_ACCESS_KEY_ID
    - AWS_SQS_SECRET_ACCESS_KEY

    Steps:
    1. Initializes the SQS client using `boto3` with the specified AWS credentials and region.
    2. Iterates through the list of queues.
    3. Checks if each queue exists:
       - If it exists, the queue URL is displayed.
       - If it does not exist, the queue is created.
    4. Logs the result of each operation (success or error) to the console.

    Raises:
    - ClientError: If there is an issue with AWS credentials or SQS operations.

    Usage:
        python manage.py create_sqs_queues
    """
    
    help = 'Create SQS Queues'

    def handle(self, *args, **kwargs):
        # Initialize SQS client
        sqs_client = boto3.client(
            'sqs',
            region_name=AWS_SQS_REGION,
            aws_access_key_id=AWS_SQS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SQS_SECRET_ACCESS_KEY
        )

        # List of queues to create
        queues = [
            AWS_SQS_QUEUE,
            AWS_SQS_CONDITION_QUEUE,
            AWS_SQS_ENCOUNTER_QUEUE,
            AWS_SQS_MEDICATION_REQUEST_QUEUE,
            AWS_SQS_DOCUMENT_REFERENCE_QUEUE
        ]

        for queue in queues:
            try:
                # Check if the queue already exists
                response = sqs_client.get_queue_url(QueueName=queue)
                self.stdout.write(self.style.SUCCESS(f'Queue "{queue}" already exists at {response["QueueUrl"]}'))
            except ClientError as e:
                if e.response['Error']['Code'] == 'AWS.SimpleQueueService.NonExistentQueue':
                    # Create the queue if it does not exist
                    sqs_client.create_queue(QueueName=queue)
                    self.stdout.write(self.style.SUCCESS(f'Queue "{queue}" created successfully'))
                else:
                    self.stdout.write(self.style.ERROR(f'Error checking/creating queue "{queue}": {e}'))

        
