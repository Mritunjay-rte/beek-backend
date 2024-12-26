"""
API Response Handlers
"""
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST


class SuccessResponse(Response):
    """
    Response class for success responses
    """

    def __init__(self, status_code=HTTP_200_OK, * args, **kwargs):
        '''
        :param status: default status 200
        '''
        response = {
            'status': "success",
            'message': kwargs.get('message', ""),
            'data': kwargs.get('data', {})
        }
        super(SuccessResponse, self).__init__(
            data=response, status=status_code)


class ErrorResponse(Response):
    """
    Response class for success responses
    """

    def __init__(self, status_code=HTTP_400_BAD_REQUEST, * args, **kwargs):
        '''
        :param status: default status 200
        '''
        response = {
            'status': "error",
            'message': kwargs.get('message', ""),
            'errors': kwargs.get('errors', {})
        }
        super(ErrorResponse, self).__init__(
            data=response, status=status_code)
