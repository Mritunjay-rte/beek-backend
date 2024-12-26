# BeekHealthBackend
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Django](https://img.shields.io/badge/Django-4.2-green?style=flat&logo=django&logoColor=white)](https://www.djangoproject.com/)
[![Django REST Framework](https://img.shields.io/badge/Django%20REST%20Framework-3.15.2-FF69B4?style=flat)](https://www.django-rest-framework.org/)
[![PostgreSQL 16](https://img.shields.io/badge/PostgreSQL-16.0-336791?style=flat&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Stripe](https://img.shields.io/badge/Stripe-6772E5?style=flat&logo=stripe&logoColor=white)](https://stripe.com/)
[![JWT](https://img.shields.io/badge/PyJWT-2.9.0-8C1F29?style=flat)](https://pyjwt.readthedocs.io/en/stable/)
[![Daphne](https://img.shields.io/badge/Daphne-4.1.2-005f9e?style=flat&logo=python&logoColor=white)](https://www.djangoproject.com/)
[![Celery](https://img.shields.io/badge/Celery-5.4.0-37814A?style=flat&logo=celery&logoColor=white)](https://docs.celeryproject.org/)
[![Gunicorn](https://img.shields.io/badge/Gunicorn-23.0.0-499848?style=flat&logo=gunicorn&logoColor=white)](https://gunicorn.org/)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0.32-ff6347?style=flat&logo=python&logoColor=white)](https://www.sqlalchemy.org/)
[![Pillow](https://img.shields.io/badge/Pillow-10.4.0-8A2BE2?style=flat&logo=python&logoColor=white)](https://python-pillow.org/)
[![Boto3](https://img.shields.io/badge/Boto3-1.35.24-4A9BD8?style=flat&logo=amazon-aws&logoColor=white)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
[![Channels](https://img.shields.io/badge/Channels-4.1.0-0d96f2?style=flat&logo=python&logoColor=white)](https://channels.readthedocs.io/)

This document provides the steps to initialize and run the application in local.

## Prerequisites

Before running the application, ensure the following are installed or configured:

- Python 3.12.x
- Postgres 16

### Environment Variables

1. **Rename the `.env.sample` file to `.env`:**

    ```bash
    cp .env.sample .env
    ```

2. **Fill in your secrets and configurations in the `.env` file**. 
    - This includes sensitive information such as your `SECRET_KEY`, database credentials, and other environment-specific settings.  
    - Refer to the [Environment Variables Documentation](ENV_Documentation.md) for detailed information on each variable. 



## Setup Instructions



Follow the steps below to set up and run the applications.

### Main Application Setup

1. **Navigate to the project folder:**

   ```bash
   cd api/Beek/
   ```

2. **Create and activate a virtual environment (optional):**

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install Dependencies:**

   ```bash
   pip install --no-cache-dir -r requirements.txt
   pip install gunicorn==23.0.0
   pip install 'uvicorn[standard]==0.31.0'
   ```

4. **Run the Initialization Script:**

   The `initialize.sh` script will handle tasks such as collecting static files, creating and applying database migrations, loading initial data, and creating a super admin.

   ```bash
   chmod +x initialize.sh
   ./initialize.sh
   ```

5. **Run the Application:**

   ```bash
   python manage.py runserver 0:8000
   ```

   _The main application can be accessed at `http://localhost:8000/`, and the Swagger API documentation can be found at `http://localhost:8000/swagger/`._

---

### Worker Application Setup

The "Worker" application in `worker/Worker/` is responsible for data processing and should be run before the main application, on port 8001.

1. **Navigate to the Worker folder:**

   ```bash
   cd worker/Worker/
   ```

   _You can skip steps 2 and 3 if you are not using a virtual environment or are using the same virtual environment for both applications._

2. **Create and activate a virtual environment (optional):**

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install Dependencies:**

   ```bash
   pip install --no-cache-dir -r requirements.txt
   ```

4. **Run Celery Workers:**

   After installing the dependencies, start the Celery workers. Each of the following commands must be run in a **separate command prompt/terminal**:

   1. **Default Worker**:
      ```bash
      celery -A worker worker --loglevel=info
      ```

   2. **Encounter Queue Worker**:
      ```bash
      celery -A worker worker -l info -Q beek-encounter-queue-loc
      ```

   3. **Condition Queue Worker**:
      ```bash
      celery -A worker worker -l info -Q beek-condition-queue-loc
      ```

   4. **Medication Request Queue Worker**:
      ```bash
      celery -A worker worker -l info -Q beek-medication-request-queue-loc
      ```

   5. **Document Reference Queue Worker**:
      ```bash
      celery -A worker worker -l info -Q beek-document-reference-queue-loc
      ```
   _Note: The names of the queues can be changed, but they must match the values specified in the `.env` file. The suffix `-loc` is used here to indicate that these are for local or development environments._


5. **Run Celery Beat (optional):**  

   If you need scheduled tasks, you can run Celery Beat in a **separate command prompt/terminal**:  

   ```bash  
   celery -A worker beat -l info  
   ```  

---

### Additional Information

- **Super Admin**: Ensure the super admin is created successfully.
- **Static Files**: Ensure static files are collected successfully.
- **Database**: Migrations are created and applied to ensure your database is up to date with the latest models.
- **Queues**: Ensure queues are created successfully.

_The status will be given while executing the `Initialization Script`._

