# Generated by Django 4.2 on 2024-09-25 10:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0022_alter_personalinfo_current_health_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='personalinfo',
            name='excercise_time',
            field=models.CharField(blank=True, choices=[('15_minutes', '15 Minutes'), ('30_minutes', '30 Minutes'), ('45_minutes', '45 Minutes'), ('1_hour', '1 Hour'), ('more_than_1_hour', 'More than 1 Hour')], max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='personalinfo',
            name='exercise_frequency',
            field=models.CharField(blank=True, choices=[('1-3_times_per_week', '1-3 times per week'), ('4-5_times_per_week', '4-5 times per week'), ('6-7_times_per_week', '6-7 times per week'), ('occasionally', 'Occasionally'), ('never', 'Never')], max_length=20, null=True),
        ),
        migrations.AlterField(
            model_name='personalinfo',
            name='gender',
            field=models.CharField(blank=True, choices=[('male', 'Male'), ('female', 'Female'), ('female_to_male', 'Female-to-Male'), ('male_to_female', 'Male-to-Female')], max_length=15, null=True),
        ),
    ]
