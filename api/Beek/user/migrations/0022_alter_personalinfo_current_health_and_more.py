# Generated by Django 4.2 on 2024-09-24 11:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0021_personalinfo_current_health_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='personalinfo',
            name='current_health',
            field=models.CharField(blank=True, choices=[('very_unhealthy', 'Very Unhealthy'), ('unhealthy', 'Unhealthy'), ('average', 'Average'), ('healthy', 'Healthy'), ('very_healthy', 'Very Healthy')], max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='personalinfo',
            name='intensity_of_excercise',
            field=models.CharField(blank=True, choices=[('very_light_exercise', 'Very Light Exercise'), ('light_exercise', 'Light Exercise'), ('moderate_exercise', 'Moderate Exercise'), ('intense_exercise', 'Intense Exercise'), ('very_intense_exercise', 'Very Intense Exercise')], max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='personalinfo',
            name='symptom',
            field=models.CharField(blank=True, choices=[('sore_throat', 'Sore throat'), ('headache', 'Headache'), ('cough', 'Cough'), ('fever', 'Fever'), ('fatigue', 'Fatigue'), ('shortness_of_breath', 'Shortness of breath'), ('chest_pain', 'Chest pain'), ('dizziness', 'Dizziness'), ('nausea', 'Nausea'), ('muscle_aches', 'Muscle aches'), ('joint_pain', 'Joint pain'), ('other', 'Other')], max_length=100, null=True),
        ),
    ]
