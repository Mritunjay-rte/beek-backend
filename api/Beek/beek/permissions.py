from rest_framework.permissions import BasePermission
from user.models import UserSubscriptions

class HasActiveSubscription(BasePermission):
    """
    Custom permission to check if the user has an active subscription.
    """

    def has_permission(self, request, view):
        user = request.user
        if not user.is_authenticated:
            return False
        latest_subscription = UserSubscriptions.objects.filter(user=user).order_by('-created_at').first()
        return (latest_subscription and latest_subscription.status in ['trial','active', 'cancelled'])


class HasActiveSubscriptionOrAdmin(BasePermission):

    def has_permission(self, request, view):
        latest_subscription = UserSubscriptions.objects.filter(user=request.user).order_by('-created_at').first()
        has_active_subscription = latest_subscription and latest_subscription.status in ['trial','active', 'cancelled']
        is_admin = request.user.is_staff

        return (has_active_subscription or is_admin)