from decouple import config
from beek.celery import app
from celery.exceptions import CeleryError
import logging
import boto3
from urllib.parse import urlparse
import pymupdf
import io
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import InMemoryUploadedFile

logger = logging.getLogger(__name__)

AWS_SQS_QUEUE = config('AWS_SQS_QUEUE')


def send_task_on_provider_connect(message, is_initial_provider_sync):
    """
    This function initiates background sync task by calling worker function 'process_sqs_message'.

    Args:
        message (string): The users service id.
        is_initial_provider_sync (boolean): If true, then it is initial sync. Otherwise  it is a refresh sync.

    Returns:
        response: True if success, an error message if any exception arises..
    """
    try:
        response = app.send_task(
            'worker.process_sqs_message',
            args=[message, is_initial_provider_sync], 
            queue=AWS_SQS_QUEUE 
        )
        return response

    except CeleryError as e:
        logger.error(f"CeleryError occurred while sending task: {str(e)}")
        return {"status": "error", "message": "Failed to send task to Celery queue."}

    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")
        return {"status": "error", "message": "An unexpected error occurred while sending the task."}
    


def delete_file_from_s3(file_url):
    """
    This function to deletes the old file from S3, when new file is updating for existing entry.

    Args:
        file_url (string): The S3 url of the file to be deleted.

    Returns:
        response: True if success, an error message if any exception arises..
    """
    if file_url:
        bucket_name = config('S3_BUCKET_NAME')

        # Extract the file key from the file URL (remove the domain)
        parsed_url = urlparse(file_url)
        file_key = parsed_url.path.lstrip('/')
        
        s3_client = boto3.client('s3',
                                aws_access_key_id=config('S3_ACCESS_KEY'),
                                aws_secret_access_key=config('S3_SECRET_KEY')
                            )
        try:
            s3_client.delete_object(Bucket=bucket_name, Key=file_key)
        except Exception as e:
            print(f"Error deleting file from S3: {str(e)}")


def sanitize_pdf(pdf_file):
    """
    Sanitize the uploaded PDF file by removing JavaScript, annotations, and interactive content.

    Args:
        pdf_file (UploadedFile): The uploaded PDF file.
    
    Returns:
        bytes: The sanitized PDF content in bytes.
    
    Raises:
        ValidationError: If the uploaded file is not a valid PDF.
    """
    try:
        # Load the PDF from the uploaded file
        pdf_document = pymupdf.open(stream=pdf_file.read(), filetype="pdf")
    except Exception as e:
        raise ValidationError(f"Invalid PDF file: {str(e)}")
    
    # Create a new PDF writer
    new_pdf = pymupdf.Document()

    # Iterate through pages and copy sanitized content
    for page_number in range(pdf_document.page_count):
        page = pdf_document[page_number]

        # Create a new page with the same dimensions
        new_page = new_pdf.new_page(width=page.rect.width, height=page.rect.height)

        # Copy text, images, and drawings (no annotations, JS, or interactivity)
        new_page.show_pdf_page(new_page.rect, pdf_document, page_number)

    # Save the sanitized PDF to a byte buffer
    output_stream = io.BytesIO()
    new_pdf.save(output_stream, garbage=4)  # Optimize the file and remove unused objects
    new_pdf.close()
    pdf_document.close()

    # Create an InMemoryUploadedFile from the sanitized PDF
    output_stream.seek(0)  # Reset stream pointer to the start
    sanitized_pdf = InMemoryUploadedFile(
        file=output_stream,
        field_name="file",
        name=pdf_file.name,
        content_type="application/pdf",
        size=output_stream.getbuffer().nbytes,
        charset=None,
    )

    return sanitized_pdf