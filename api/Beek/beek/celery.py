from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from decouple import config

AWS_SQS_REGION = config('AWS_SQS_REGION')
AWS_SQS_ACCESS_KEY_ID = config('AWS_SQS_ACCESS_KEY_ID')
AWS_SQS_SECRET_ACCESS_KEY = config('AWS_SQS_SECRET_ACCESS_KEY')
AWS_SQS_GENERAL_URL = config('AWS_SQS_GENERAL_URL')
AWS_SQS_QUEUE = config('AWS_SQS_QUEUE')
CELERY_RESULT_BACKEND = config('CELERY_RESULT_BACKEND')

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'beek.settings')

app = Celery('beek')

app.config_from_object('django.conf:settings', namespace='CELERY')

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
        },
    },
    broker_connection_retry_on_startup=True,
    result_backend=CELERY_RESULT_BACKEND,
    result_extended=True,
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',


)
app.conf.task_protocol = 1
