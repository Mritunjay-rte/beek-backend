# Generated by Django 4.2 on 2024-09-11 08:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('health', '0009_initialdatasynclog_schedulerdatasynclog'),
    ]

    operations = [
        migrations.AddField(
            model_name='document',
            name='record_synced_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='prescription',
            name='record_synced_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]