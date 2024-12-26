from django.core.mail import EmailMessage
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from django.template.loader import render_to_string
import requests
from decouple import config
from health.models import UserServiceToken, Service
from user.models import User, MasterSubscriptionPlanPrice, UserSubscriptions
import stripe
from datetime import timedelta
from django.db.models import Case, CharField, OuterRef, Subquery, Value, When, F, ExpressionWrapper, DateField, Count,  Max, Q
from django.db.models.functions import Lower, Coalesce
from rest_framework.exceptions import ValidationError
from django.utils.timezone import now
from django.contrib.postgres.aggregates import ArrayAgg


def send_custom_email(subject, template, context, to_email):
    """
        Sends a custom email to a specified recipient using a given template.

        This function is used to send emails with dynamic content based on the provided
        context. The subject, template, and context allow for the customization of the 
        email's content. The email is sent to the recipient specified by the `to_email` address.

        Args:
            subject (str): The subject of the email.
            template (str): The template used to render the email content.
            context (dict): The context data to be passed to the template for dynamic content.
            to_email (str): The recipient's email address.

        Returns:
            None

        Raises:
            Exception: If there is an error while sending the email.
    """
    html_content = render_to_string(template, context)

    email = EmailMessage(
        subject=subject,
        body=html_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[to_email],
    )
    email.content_subtype = 'html'
    email.send()


def create_1UP_user(user):
    """
    create user in 1Up...excuted when a user signup into the system 
    """
    try:
        client_id =config('1UP_CLIENT_ID')
        client_secret =config('1UP_CLIENT_SECRET')
        headers = {
        "Content-Type": "application/json" 
        }
        url = config('1UP_BASE_URL') + "user-management/v1/user"
        data = {
        "app_user_id": str(user.id), 
        "client_id": client_id,  
        "client_secret": client_secret
    }
        response = requests.post(url, json=data, headers=headers)
        if response.status_code in [200, 201]: 
            code = response.json().get('code')
            # save code to user model
            UserServiceToken.objects.create(user=user, service=Service.objects.first(), code=code)
        else:
            print(f"Failed to retrieve data. Status code: {response.status_code}")
            print("Response:", response.text)
        return True
    except Exception as e:
        print(str(e))



def create_checkout_session(user, success_url, cancel_url,subscription_plan_price_id):
    """
    Function to generate a stripe checkout url 
    """
    try:
        stripe_obj = stripe.Customer.list(email=user.email, limit=1)
        if stripe_obj['data']:
            stripe_id = stripe_obj['data'][0]['id']
        else:
            stripe_id = create_stripe_user(user.name, user.email)
        user_obj = User.objects.get(id=user.id)
        user_obj.stripe_id = stripe_id
        user_obj.save()
    except Exception as e:
        print(e)
        return Response({"message": "Could not create customer in stripe", "data": []}, status=status.HTTP_400_BAD_REQUEST)
    try:
        pricing_id = MasterSubscriptionPlanPrice.objects.filter(id=subscription_plan_price_id, is_active=True, is_deleted=False).get()
        user_subscription = UserSubscriptions.objects.filter(user=user).first()
        trial_period_days = None if user_subscription else config('FREE_TRIAL_PERIOD_IN_DAYS')
        checkout_session = stripe.checkout.Session.create(
            success_url=success_url,
            cancel_url=cancel_url,
            subscription_data={
                'trial_period_days': trial_period_days
            },
            line_items=[
                {
                    "price": pricing_id.stripe_id,
                    "quantity": 1,
                },
            ],
            mode="subscription",
            customer=stripe_id,
            customer_update={
                "address": "auto",
                "name": "never"
            },
            payment_method_collection="always"
        )
        stripe_data = {}
        stripe_data['url'] = checkout_session['url']
        return stripe_data
    except Exception as e:
        print(e)


def create_stripe_user(name, email):
    """
    create user in stripe account
    """
    try:
        customer = stripe.Customer.create(
            name=name,
            email=email
        )
        return customer['id']
    except Exception:
        pass



def get_user_report_queryset(base_queryset, ordering=None):
        """
        function for user report queryset 
        params : 
            base_queryset - queryset
            ordering - used for sorting the queryset 
        """
        # Prepare the base queryset with annotations
        latest_subscription = UserSubscriptions.objects.filter(
            user=OuterRef('pk')
        ).order_by('-created_at')
        annotated_queryset = base_queryset.annotate(
            latest_status=Subquery(latest_subscription.values('status')[:1]),
            subscription_status=Case(
                When(deleted_at__isnull=False, then=Value('Terminated')),
                When(latest_status='trial', then=Value('Trial')),
                When(latest_status='expired', then=Value('Expired')),
                When(latest_status__in=['active', 'cancelled'], then=Value('Active')),
                default=Value('Pending'),
                output_field=CharField()
            ),
            billing_period_start=Case(
                When(
                    subscription_status='Trial',
                    then=Value(None, output_field=DateField())
                ),
                default=Subquery(latest_subscription.values('billing_period_start')[:1]),
                output_field=DateField(),
            ),
            billing_period_end=Case(
                When(
                    subscription_status__in=['Expired', 'Trial', 'Terminated'],
                    then=Value(None, output_field=DateField())
                ),
                default=ExpressionWrapper(
                    Subquery(latest_subscription.values('billing_period_end')[:1]) + timedelta(hours=1),
                    output_field=DateField()
                ),
                output_field=DateField(),
            )
        )

        # Retrieve the ordering parameter from the request
        if ordering:
            try:
                if ordering.startswith('-'):
                    field_name = ordering[1:]
                    is_descending = True
                else:
                    field_name = ordering
                    is_descending = False

                # Check if the field is a valid field on the model or annotation
                if field_name in ['billing_period_start', 'billing_period_end']:
                    field_type = 'DateTimeField'
                elif field_name == 'subscription_status':
                    field_type = 'CharField'
                else:
                    field_type = annotated_queryset.model._meta.get_field(field_name).get_internal_type()

                # Apply ordering based on the field type
                if field_type == 'DateTimeField':
                    if is_descending:
                        annotated_queryset = annotated_queryset.order_by(F(field_name).desc())
                    else:
                        annotated_queryset = annotated_queryset.order_by(F(field_name))
                else:
                    if is_descending:
                        annotated_queryset = annotated_queryset.order_by(Lower(F(field_name)).desc())
                    else:
                        annotated_queryset = annotated_queryset.order_by(Lower(F(field_name)))

            except Exception as e:
                raise ValidationError(f"Invalid ordering field: {field_name}. Error: {str(e)}")

        return annotated_queryset




def get_user_api_usage_report_queryset(base_queryset, ordering=None):
        """
        function for user report queryset 
        params : 
            base_queryset - queryset
            ordering - used for sorting the queryset 
        """

        annotated_queryset = base_queryset.annotate(
            provider_count=Count('service_providers__provider', distinct=True),  # Count distinct providers
            provider_names=ArrayAgg('service_providers__provider__name', distinct=True),  # List of provider names
            total_api_calls=Count('external_api_log', distinct=True),  # Total API calls
            initial_api_calls=Count('external_api_log', filter=Q(external_api_log__is_initial_sync=True), distinct=True),  # Initial API calls
            refresh_api_calls=Count('external_api_log', filter=Q(external_api_log__is_initial_sync=False), distinct=True),  # Refresh API calls
            last_api_call=Coalesce(Max('external_api_log__requested_at'), Value(None)),  # Last API call timestamp
            user_status=Case(
                When(deleted_at__isnull=False, then=Value("Deleted")),
                When(is_blocked=True, then=Value("Restricted")),
                When(
                    last_login_at__gte=now() - timedelta(days=30),
                    then=Value("Active"),
                ),
                default=Value("Inactive"),
                output_field=CharField(),
            ),
        )
        # Retrieve the ordering parameter from the request
        if ordering:
            try:
                if ordering.startswith('-'):
                    field_name = ordering[1:]
                    is_descending = True
                else:
                    field_name = ordering
                    is_descending = False

                annotated_fields = {
                    'last_api_call': 'DateTimeField',
                    'user_status': 'CharField',
                    'provider_count': 'IntegerField',
                    'total_api_calls': 'IntegerField',
                    'initial_api_calls': 'IntegerField',
                    'refresh_api_calls': 'IntegerField',
                }

                # Check if the field is a valid field on the model or annotation
                if field_name in annotated_fields:
                    field_type = annotated_fields[field_name]
                else:
                    field_type = annotated_queryset.model._meta.get_field(field_name).get_internal_type()

                # Apply ordering based on the field type
                if field_type in ['DateTimeField', 'IntegerField']:
                    if is_descending:
                        annotated_queryset = annotated_queryset.order_by(F(field_name).desc())
                    else:
                        annotated_queryset = annotated_queryset.order_by(F(field_name))
                else:
                    if is_descending:
                        annotated_queryset = annotated_queryset.order_by(Lower(F(field_name)).desc())
                    else:
                        annotated_queryset = annotated_queryset.order_by(Lower(F(field_name)))

            except Exception as e:
                raise ValidationError(f"Invalid ordering field: {field_name}. Error: {str(e)}")

        return annotated_queryset