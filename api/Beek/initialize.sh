#!/bin/bash

echo "Initializing application setup..."

# Collect static files
python manage.py collectstatic --noinput

# Check for model changes and create migrations
python manage.py makemigrations

# Apply database migrations
python manage.py migrate

# Load initial data (groups.json)
python manage.py loaddata groups.json

# Create a super admin
python manage.py createsuperadmin

# Create a necessary queues
python manage.py createqueue

echo "Initialization complete."
echo "You can now start the application using the following command:"
echo "python manage.py runserver 0:8000"