# Generated by Django 4.2 on 2024-10-16 11:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0027_alter_personalinfo_photo'),
    ]

    operations = [
        migrations.AlterField(
            model_name='personalinfo',
            name='is_smoker',
            field=models.BooleanField(default=None, null=True),
        ),
    ]