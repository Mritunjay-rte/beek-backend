# Generated by Django 4.2 on 2024-08-16 06:25

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(blank=True, max_length=100, null=True)),
                ('email', models.EmailField(max_length=120, unique=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_staff', models.BooleanField(default=False)),
                ('is_superuser', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('deleted_at', models.DateTimeField(blank=True, null=True)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='PersonalInfo',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('gender', models.CharField(choices=[('male', 'Male'), ('female', 'Female'), ('female_to_male', 'Female-to-Male'), ('male_to_female', 'Male-to-Female')], max_length=15)),
                ('birth_date', models.DateField()),
                ('zip_code', models.CharField(max_length=50)),
                ('height', models.CharField(max_length=50)),
                ('weight', models.CharField(max_length=50)),
                ('insurance_company_name', models.CharField(max_length=100)),
                ('insurance_no', models.CharField(max_length=50)),
                ('sponsor_name', models.CharField(max_length=100)),
                ('photo', models.ImageField(blank=True, null=True, upload_to='')),
                ('is_smoker', models.BooleanField(default=False)),
                ('exercise_frequency', models.CharField(choices=[('DAILY', 'Daily'), ('WEEKLY', 'Weekly'), ('MONTHLY', 'Monthly'), ('RARELY', 'Rarely'), ('NEVER', 'Never')], default='NEVER', max_length=7)),
                ('excercise_activities', models.JSONField(blank=True, null=True)),
                ('excercise_time', models.CharField(choices=[('30_minutes', '30 Minutes')], max_length=100)),
                ('goal', models.CharField(choices=[('general_health_monitoring', 'General Health Monitoring'), ('health_information_storage', 'Health Information Storage'), ('chronic_condition_monitoring', 'Chronic Condition Monitoring'), ('preventive_health_management', 'Preventive Health Management'), ('diagonistic_test_recommendations', 'Diagonistic Test Recommendations')], max_length=250)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('deleted_at', models.DateTimeField(blank=True, null=True)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='personal_info', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
