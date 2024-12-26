from django_filters import rest_framework as filters
from user.models import User, UserSubscriptions
from datetime import datetime, timedelta
from django.db.models import OuterRef, Subquery, Exists, Max


class UserFilter(filters.FilterSet):
    """
    A custom filter set for filtering `User` objects based on various status and date-related criteria.

    This filter set is used to filter users based on their subscription status, user status, last login date, 
    and account creation date.

    Filters:
        - `user_status`: Filters users based on their status (e.g., 'active', 'inactive', 'restricted', 'deleted').
        - `subscription_status`: Filters users based on their subscription status (e.g., 'active', 'trial', 'expired', 'terminated').
        - `last_login`: Filters users based on their last login date.
        - `created_at`: Filters users based on their account creation date.

    Methods:
        - `filter_user_status(queryset, name, value)`: Filters users by user status, such as active, inactive, restricted, or deleted.
        - `filter_subscription_status(queryset, name, value)`: Filters users by subscription status, including active, trial, expired, and terminated.
    """
    
    subscription_status = filters.CharFilter(method='filter_subscription_status')
    user_status = filters.CharFilter(method='filter_user_status')
    last_login = filters.DateTimeFilter(field_name='last_login_at', lookup_expr='date')
    created_at = filters.DateTimeFilter(field_name='created_at', lookup_expr='date')

    def filter_user_status(self, queryset, name, value):
        if value.lower() == 'active':
            thirty_days_ago = datetime.now() - timedelta(days=30)
            return queryset.filter(last_login_at__gte=thirty_days_ago, is_blocked=False, deleted_at__isnull=True)
        elif value.lower() == 'inactive':
            thirty_days_ago = datetime.now() - timedelta(days=30)
            return queryset.filter(last_login_at__lte=thirty_days_ago, is_blocked=False, deleted_at__isnull=True)
        elif value.lower() == 'restricted':
            return queryset.filter(is_blocked=True, deleted_at__isnull=True)
        elif value.lower() == 'deleted':
            return queryset.filter(deleted_at__isnull=False)
        else:
            return queryset.none()

    def filter_subscription_status(self, queryset, name, value):
        if value.lower() == 'terminated':
            return queryset.filter(deleted_at__isnull=False)
        latest_subscription = UserSubscriptions.objects.filter(
            user=OuterRef('pk')).order_by('-created_at').values('status')[:1] 
        queryset = queryset.annotate(latest_subscription_status=Subquery(latest_subscription))
        if value.lower() == 'active':
            print("Filtering for active subscriptions")
            return queryset.filter(deleted_at__isnull=True,
                latest_subscription_status__in=['active', 'cancelled']
            ).distinct()
        elif value.lower() == 'trial':
            return queryset.filter(deleted_at__isnull=True,
                latest_subscription_status='trial'
            ).distinct()
        elif value.lower() == 'expired':
            expired_users_queryset = queryset.filter(latest_subscription_status='expired', deleted_at__isnull=True).distinct()
            no_subscription_users = queryset.filter(~Exists(UserSubscriptions.objects.filter(user=OuterRef('pk'))), deleted_at__isnull=True).distinct()
            return expired_users_queryset | no_subscription_users
        else:
            return queryset.none()


    class Meta:
        model = User
        fields = ['user_status', 'last_login', 'created_at', 'subscription_status']

    

class UserReportFilter(filters.FilterSet):
    """
    A custom filter set for filtering `User` objects based on subscription status, creation date, 
    last login date, and billing period start date.

    This filter set is used to filter users in a user report context, allowing for the following filters:
    - `subscription_status`: Filters users by the status of their subscription (e.g., active, expired).
    - `created_at`: Filters users by their account creation date within a specified date range.
    - `last_login_at`: Filters users by the last login date within a specified date range.
    - `billing_period_start`: Filters users by the start date of their billing period, typically used for filtering payment history.

    Filters:
        - `subscription_status`: A string representing the subscription status (e.g., 'active', 'expired'). Filters users based on their subscription status.
        - `created_at`: A date range filter for the `created_at` field, used to filter users who were created within a specified date range.
        - `last_login_at`: A date range filter for the `last_login_at` field, used to filter users by their last login date.
        - `billing_period_start`: A date range filter for the `billing_period_start` field, typically used to filter users based on their last payment or billing period start.

    Methods:
        - `filter_created_at_by_date(queryset, name, value)`: Filters users by the `created_at` field within a specified date range.
        - `filter_last_login_at_by_date(queryset, name, value)`: Filters users by the `last_login_at` field within a specified date range.
        - `filter_billing_period_start(queryset, name, value)`: Filters users by the `billing_period_start` field within a specified date range.
        - `filter_subscription_status(queryset, name, value)`: Filters users by their subscription status (e.g., 'active', 'expired').
    """
    subscription_status = filters.CharFilter(method='filter_subscription_status')
    created_at = filters.DateFromToRangeFilter(method='filter_created_at_by_date')
    last_login_at = filters.DateFromToRangeFilter(method='filter_last_login_at_by_date')
    billing_period_start = filters.DateFromToRangeFilter(method='filter_billing_period_start')#last payment

    def filter_created_at_by_date(self, queryset, name, value):
        """
        Filter `created_at` with the `date` lookup and range.
        """
        if value.start and value.stop:
            return queryset.filter(
                created_at__date__gte=value.start,
                created_at__date__lte=value.stop
            )
        elif value.start:
            return queryset.filter(created_at__date__gte=value.start)
        elif value.stop:
            return queryset.filter(created_at__date__lte=value.stop)
        return queryset
    
    def filter_last_login_at_by_date(self, queryset, name, value):
        """
        Filter `last_login_at` with the `date` lookup and range.
        """
        if value.start and value.stop:
            return queryset.filter(
                last_login_at__date__gte=value.start,
                last_login_at__date__lte=value.stop
            )
        elif value.start:
            return queryset.filter(last_login_at__date__gte=value.start)
        elif value.stop:
            return queryset.filter(last_login_at__date__lte=value.stop)
        return queryset
    
    def filter_billing_period_start(self, queryset, name, value):
        """
        Filter `billing_period_start` with the `date` lookup and range.
        """
        if value.start and value.stop:
            return queryset.filter(
                billing_period_start__gte=value.start,
                billing_period_start__lte=value.stop
            )
        elif value.start:
            return queryset.filter(billing_period_start__gte=value.start)
        elif value.stop:
            return queryset.filter(billing_period_start__lte=value.stop)
        return queryset

    def filter_subscription_status(self, queryset, name, value):
        if value:
            lst_value = value.split(',')
            return queryset.filter(**{f"{name}__in": lst_value})
        return queryset

    class Meta:
        model = User
        fields = ['created_at', 'subscription_status', 'last_login_at', 'billing_period_start']


class UserAPIUsageReportFilter(filters.FilterSet):
    """
    A custom filter set for filtering `User` objects based on provider, user status, and last login date.

    This filter set is used to filter users in the `UserAPIUsageReport` context, allowing for the following filters:
    - `provider`: Filters users by the reference number of associated service providers.
    - `user_status`: Filters users by their account status (e.g., active, inactive, blocked).
    - `last_login_at`: Filters users based on the date of their last login within a specified date range.

    Filters:
        - `provider`: A comma-separated list of provider reference number. Filters users who have associated service providers with those reference number.
        - `user_status`: A comma-separated list of user statuses (e.g., 'Active', 'Inactive'). Filters users based on their current account status.
        - `last_login_at`: A date range filter for the `last_login_at` field, which can filter users who logged in within a specific date range.

    Methods:
        - `filter_provider(queryset, name, value)`: Filters users by the reference number of their associated service providers.
        - `filter_user_status(queryset, name, value)`: Filters users by their user status (e.g., 'Active', 'Inactive').
        - `filter_last_login_at_by_date(queryset, name, value)`: Filters users by the date range of their `last_login_at` field.
    """
    provider = filters.CharFilter(method='filter_provider')
    user_status = filters.CharFilter(method='filter_user_status')
    last_login_at = filters.DateFromToRangeFilter(method='filter_last_login_at_by_date')

    def filter_provider(self, queryset, name, value):
        """
        Filter `User` by provider name.

        """
        if value:
            lst_value = value.split(',')
            return queryset.filter(
                service_providers__provider__reference__in=lst_value
            )
        return queryset

    
    def filter_last_login_at_by_date(self, queryset, name, value):
        """
        Filter `last_login_at` with the `date` lookup and range.
        """
        if value.start and value.stop:
            return queryset.filter(
                last_login_at__date__gte=value.start,
                last_login_at__date__lte=value.stop
            )
        elif value.start:
            return queryset.filter(last_login_at__date__gte=value.start)
        elif value.stop:
            return queryset.filter(last_login_at__date__lte=value.stop)
        return queryset
    

    def filter_user_status(self, queryset, name, value):
        if value:
            lst_value = value.split(',')
            return queryset.filter(**{f"{name}__in": lst_value})
        return queryset