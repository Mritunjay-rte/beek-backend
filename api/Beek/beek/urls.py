"""
URL configuration for beek project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.urls import path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from health.views import ConnectToProvider, ConnectToProviderCallback
from user.views import SubscriptionListView
from decouple import config
from beek import settings
from django.views.generic import RedirectView
from hcpt.views import CPTListView

schema_view = get_schema_view(
    openapi.Info(
        title="BEEK API",
        default_version='v1',
        description="API documentation for Beek"
    ),
    public=True,
    url=config('BACKEND_URL'),  # make sure this is needed for https
    permission_classes=(permissions.AllowAny,),
    authentication_classes=(),
)

conditional_patterns = [
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
]

urlpatterns = []

if not settings.DEBUG:
    urlpatterns += [path('', RedirectView.as_view(url=config('FE_URL')))]

urlpatterns += [
    path('ULs1ClLDecT9yPbD/', admin.site.urls), # django admin panel api
    path('api/user/', include('user.urls')),
    path('api/health/', include('health.urls')),
    path('provider/connect/', ConnectToProvider.as_view(), name='provider-connect'),
    path('provider/callback/', ConnectToProviderCallback.as_view(),name='provider-callback'),
    path('api/subscription/plans/', SubscriptionListView.as_view(), name='subscription-plans'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('api/find-cpt/', CPTListView.as_view(), name='find-cpt'),
]

if settings.DEBUG:
    urlpatterns = urlpatterns + conditional_patterns