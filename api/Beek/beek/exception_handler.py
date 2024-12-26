from rest_framework.views import exception_handler
from beek.responses import ErrorResponse
from rest_framework import status


def custom_exception_handler(exc, context):

    response = exception_handler(exc, context)
    if response is not None:
        error_text = response.status_text.replace(" ", "_")

        if not 'detail' in response.data:
            data = response.data
            response.data = {}
            response.data['message'] = error_text
            if data:
                response.data['errors'] = data
                response.data['message'] = 'VALIDATION_ERROR'

            return ErrorResponse(message=response.data['message'], errors=response.data['errors'], status_code=response.status_code)
        elif getattr(response.data['detail'], 'code', '') == 'authentication_failed':
            return ErrorResponse(message='Unauthorized', errors=response.data, status_code=status.HTTP_401_UNAUTHORIZED)
       
        return ErrorResponse(message=response.status_text, errors=response.data, status_code=response.status_code)