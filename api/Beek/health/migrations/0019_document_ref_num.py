# Generated by Django 4.2 on 2024-10-01 11:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('health', '0018_alter_document_files'),
    ]

    operations = [
        migrations.AddField(
            model_name='document',
            name='ref_num',
            field=models.CharField(blank=True, max_length=250, null=True),
        ),
    ]
