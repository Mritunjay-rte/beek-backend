# Generated by Django 4.2 on 2024-08-22 08:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0006_logstripewebhook_mastersubscriptionplan_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='stripe_id',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
    ]
