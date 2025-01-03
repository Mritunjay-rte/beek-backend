from django.urls import re_path

from .consumers import ChatConsumer

websocket_urlpatterns = [
    re_path(r'ws/sync/(?P<room_name>[^/]+)$', ChatConsumer.as_asgi()),
]