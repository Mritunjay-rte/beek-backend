from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from beek.responses import SuccessResponse


class StandardPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 1000

    def get_paginated_response(self, data):
        return SuccessResponse(message="",
            data = {
            'next': self.get_next_link(),
            'previous': self.get_previous_link(),
            'recordsTotal': self.page.paginator.count,
            'total_pages': self.page.paginator.num_pages,
            'result': data
        })

