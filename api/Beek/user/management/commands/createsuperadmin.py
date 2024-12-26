from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

from decouple import config


class Command(BaseCommand):
    """
    Django management command to create a superadmin user.

    This command checks if a superadmin user with the specified email already exists. 
    If not, it creates a new superadmin user with the provided email and password, 
    adds the user to the 'SUPER ADMIN' group, and logs the success of each operation.

    Steps:
    1. Retrieves the user model using `get_user_model()`.
    2. Checks if a superadmin user exists by filtering on the `SUPERUSER_EMAIL`.
    3. If the superadmin does not exist:
       - Creates a superadmin using the `SUPERUSER_EMAIL` and `SUPERUSER_PASSWORD`.
       - Adds the newly created superadmin to the 'SUPER ADMIN' group if not already part of it.
    4. Logs success or warning messages based on the operation outcome:
       - Successfully creates the superadmin and adds them to the group.
       - Warns if the superadmin already exists or is already part of the 'SUPER ADMIN' group.

    Configuration:
    - `SUPERUSER_EMAIL`: The email address for the superadmin.
    - `SUPERUSER_PASSWORD`: The password for the superadmin.

    Usage:
        python manage.py create_superadmin
    """
    
    help = 'Create a superadmin user'

    def handle(self, *args, **kwargs):
        User = get_user_model()
        if not User.objects.filter(email=config("SUPERUSER_EMAIL")).exists():
            user = User.objects.create_superuser(
                email=config("SUPERUSER_EMAIL"),
                password=config("SUPERUSER_PASSWORD")
            )
            self.stdout.write(self.style.SUCCESS('Superadmin created successfully!'))
            admin_group = Group.objects.get(name='SUPER ADMIN')
            if not user.groups.filter(name='SUPER ADMIN').exists():
                admin_group.user_set.add(user)
                self.stdout.write(self.style.SUCCESS('Superadmin added to admin group!'))
            else:
                self.stdout.write(self.style.WARNING('Superadmin already in admin group.'))
        else:
            self.stdout.write(self.style.WARNING('Superadmin already exists.'))

        
