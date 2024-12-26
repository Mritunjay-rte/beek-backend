"""
ASGI config for beek project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/asgi/
"""

import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from channels.security.websocket import OriginValidator
from django.core.asgi import get_asgi_application
from health.routing import websocket_urlpatterns
from django.conf import settings

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'beek.settings')

django_asgi_app = get_asgi_application()
allowed_hosts = settings.ALLOWED_HOSTS
application = ProtocolTypeRouter({
    'http': django_asgi_app,
    'websocket': 
    # AllowedHostsOriginValidator(
    # OriginValidator(
        AuthMiddlewareStack(URLRouter(websocket_urlpatterns))
        # allowed_hosts
    # )
})