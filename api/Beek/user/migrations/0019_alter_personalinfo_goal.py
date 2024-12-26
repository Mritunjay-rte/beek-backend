# Generated by Django 4.2 on 2024-09-23 10:13

from django.db import migrations, models
import user.models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0018_alter_personalinfo_excercise_time_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='personalinfo',
            name='goal',
            field=models.JSONField(blank=True, null=True, validators=[user.models.validate_goals]),
        ),
    ]