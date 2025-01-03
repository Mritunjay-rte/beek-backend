# Generated by Django 4.2 on 2024-11-15 11:11

from django.db import migrations, models

def populate_user_ids(apps, schema_editor):
    User = apps.get_model('user', 'User')
    last_id = 0
    for user in User.objects.all().order_by('created_at'):
        last_id += 1
        user.user_id = f"BHU{last_id:06d}"
        user.save()

class Migration(migrations.Migration):

    dependencies = [
        ('user', '0028_alter_personalinfo_is_smoker'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='user_id',
            field=models.CharField(blank=True, max_length=10, null=True),
        ),
        migrations.RunPython(populate_user_ids),  
    ]
