# Generated by Django 4.2.16 on 2024-12-30 07:24

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ("health", "0030_rename_is_sucess_response_externalapilog_is_success_response"),
    ]

    operations = [
        migrations.CreateModel(
            name="EvexiaMenu",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("product_id", models.IntegerField(blank=True, null=True)),
                (
                    "product_name",
                    models.CharField(blank=True, max_length=255, null=True),
                ),
                ("lab_id", models.IntegerField(blank=True, null=True)),
                ("is_panel", models.BooleanField(default=False)),
                (
                    "sales_price",
                    models.DecimalField(
                        blank=True, decimal_places=2, max_digits=10, null=True
                    ),
                ),
                ("test_code", models.CharField(blank=True, max_length=100, null=True)),
                ("is_kit", models.BooleanField(default=False)),
                ("lab_name", models.CharField(blank=True, max_length=255, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "db_table": "health_evexia_menu",
            },
        ),
        migrations.CreateModel(
            name="EvexiaOrders",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("patient_id", models.CharField(blank=True, max_length=255, null=True)),
                (
                    "patient_order_id",
                    models.CharField(
                        blank=True, max_length=255, null=True, unique=True
                    ),
                ),
                (
                    "product_id",
                    models.CharField(
                        blank=True, max_length=255, null=True, unique=True
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "documents",
                    models.FileField(blank=True, null=True, upload_to="receipts/"),
                ),
                (
                    "payment_status",
                    models.CharField(blank=True, max_length=255, null=True),
                ),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "db_table": "health_evexia_orders",
            },
        ),
        migrations.CreateModel(
            name="EvexiaPatient",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "patient_id",
                    models.CharField(
                        blank=True, max_length=255, null=True, unique=True
                    ),
                ),
                ("external_client_id", models.UUIDField(blank=True, null=True)),
                ("user_id", models.UUIDField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "db_table": "health_evexia_patient",
            },
        ),
        migrations.CreateModel(
            name="EvexiaPayment",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("patient_id", models.CharField(blank=True, max_length=255, null=True)),
                ("payment_id", models.CharField(blank=True, max_length=255, null=True)),
                (
                    "patient_order_id",
                    models.CharField(blank=True, max_length=255, null=True),
                ),
                (
                    "total_amount",
                    models.DecimalField(
                        decimal_places=2,
                        help_text="Total amount for the payment in USD or applicable currency.",
                        max_digits=10,
                    ),
                ),
                (
                    "payment_status",
                    models.CharField(
                        help_text="Payment status (e.g., succeeded, failed, pending).",
                        max_length=50,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Evexia Order Payment",
                "verbose_name_plural": "Evexia Order Payments",
                "db_table": "health_evexia_payments",
            },
        ),
    ]