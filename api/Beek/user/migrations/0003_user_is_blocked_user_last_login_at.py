# Generated by Django 4.2 on 2024-08-19 11:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0002_otp'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_blocked',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='user',
            name='last_login_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
