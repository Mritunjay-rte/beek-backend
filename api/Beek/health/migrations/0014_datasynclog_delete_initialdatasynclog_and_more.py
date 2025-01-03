# Generated by Django 4.2 on 2024-09-24 10:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('health', '0013_document_files_alter_document_category_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='DataSyncLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('resource', models.CharField(choices=[('encounter', 'encounter'), ('condition', 'condition'), ('prescription', 'prescription'), ('document', 'document')], max_length=100)),
                ('user_service_id', models.CharField(max_length=150)),
                ('user', models.CharField(max_length=150)),
                ('task_id', models.CharField(max_length=150)),
                ('is_complete', models.BooleanField(default=False)),
                ('error_msg', models.JSONField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('no_of_records', models.IntegerField(default=0)),
                ('completed_count', models.IntegerField(default=0)),
                ('total_count', models.IntegerField(default=0)),
                ('is_initial_sync', models.BooleanField(default=False)),
            ],
        ),
        migrations.DeleteModel(
            name='InitialDataSyncLog',
        ),
        migrations.DeleteModel(
            name='SchedulerDataSyncLog',
        ),
    ]
