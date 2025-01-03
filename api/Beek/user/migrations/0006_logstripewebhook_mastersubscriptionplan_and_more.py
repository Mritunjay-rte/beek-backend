# Generated by Django 4.2 on 2024-08-22 08:31

from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0005_user_is_email_notifications_enabled_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='LogStripeWebhook',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('stripe_id', models.CharField(blank=True, max_length=200, null=True)),
                ('event_name', models.CharField(blank=True, max_length=200, null=True)),
                ('stripe_response', models.JSONField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='MasterSubscriptionPlan',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('start_date', models.DateField(blank=True, null=True)),
                ('end_date', models.DateField(blank=True, null=True)),
                ('stripe_id', models.CharField(blank=True, max_length=200, null=True)),
                ('is_active', models.BooleanField(default=False)),
                ('is_deleted', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='MasterSubscriptionPlanPrice',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False)),
                ('price', models.DecimalField(decimal_places=2, max_digits=5, validators=[django.core.validators.MinValueValidator(0.0), django.core.validators.MaxValueValidator(9999.99)])),
                ('frequency_in_months', models.IntegerField(choices=[(12, 'Annual')])),
                ('stripe_id', models.CharField(blank=True, max_length=200, null=True)),
                ('is_active', models.BooleanField(default=False)),
                ('is_deleted', models.BooleanField(default=False)),
                ('subscription_plan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='plan_price', to='user.mastersubscriptionplan')),
            ],
        ),
        migrations.CreateModel(
            name='UserSubscriptions',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False, unique=True)),
                ('stripe_id', models.CharField(blank=True, max_length=200, null=True)),
                ('stripe_status', models.CharField(blank=True, max_length=200, null=True)),
                ('is_active', models.BooleanField(default=False)),
                ('is_expired', models.BooleanField(default=False)),
                ('is_deleted', models.BooleanField(default=False)),
                ('payment_method_deleted', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now_add=True)),
                ('billing_period_start', models.DateTimeField(auto_now_add=True)),
                ('billing_period_end', models.DateTimeField(blank=True, null=True)),
                ('cancelled_on', models.DateTimeField(blank=True, null=True)),
                ('subscription_plan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='subscription_plans', to='user.mastersubscriptionplanprice')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='subscriptions', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Transactions',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False, unique=True)),
                ('stripe_id', models.CharField(blank=True, max_length=200, null=True)),
                ('payment_link_id', models.CharField(blank=True, max_length=200, null=True)),
                ('payment_link', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('amount', models.DecimalField(decimal_places=2, max_digits=5, validators=[django.core.validators.MinValueValidator(0.0)])),
                ('status', models.CharField(blank=True, max_length=200, null=True)),
                ('payment_mode', models.CharField(blank=True, max_length=200, null=True)),
                ('is_deleted', models.BooleanField(default=False)),
                ('stripe_response', models.JSONField(blank=True, null=True)),
                ('payment_method_change', models.BooleanField(default=False)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='transactions', to=settings.AUTH_USER_MODEL)),
                ('user_subscription', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='user_subscriptions', to='user.usersubscriptions')),
            ],
        ),
    ]
