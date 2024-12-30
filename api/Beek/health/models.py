from django.db import models
from user.models import User
import uuid
from decouple import config

def dynamic_upload_path(instance, filename):
    folder_prefix = config('S3_BUCKET_FOLDER_PREFIX')
    model_name = instance.__class__.__name__.lower()
    return f"{folder_prefix}_{model_name}/{uuid.uuid4()}_{filename}"


class Service(models.Model):
    """
    Model representing a service (e.g., 1up Health, OneRecord).

    Attributes:
        id (UUID): The unique identifier for the service.
        name (str): The name of the service.
        is_active (bool): A flag indicating whether the service is active.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=120)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        """
        Returns a string representation of the service.

        Returns:
            str: The unique identifier (ID) of the service.
        """
        return str(self.id)


class Provider(models.Model):
    """
    Model representing a healthcare provider (e.g., Care Evolution, Epic, Cerner).

    Attributes:
        id (UUID): The unique identifier for the provider.
        name (str): The name of the provider.
        reference (str): A reference or identifier associated with the provider.
        is_active (bool): A flag indicating whether the provider is active.

    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=120)
    reference = models.CharField(max_length=120)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        """
        Returns a string representation of the provider.

        Returns:
            str: The unique identifier (ID) of the provider.
        """
        return str(self.id)


class ServiceProvider(models.Model):
    """
    Model representing a relationship between a service, provider, and user.

    Attributes:
        id (UUID): The unique identifier for the service provider record.
        provider (ForeignKey): The provider associated with the service.
        service (ForeignKey): The service associated with the provider.
        user (ForeignKey): The user associated with the service provider relationship.
        created_at (datetime): The date and time when the record was created.
        updated_at (datetime): The date and time when the record was last updated.
        deleted_at (datetime, optional): The date and time when the record was deleted, if applicable.

    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    provider = models.ForeignKey(
        Provider, on_delete=models.CASCADE, related_name="service_providers")
    service = models.ForeignKey(
        Service,  on_delete=models.CASCADE, related_name="service_providers")
    user = models.ForeignKey(
        User,  on_delete=models.CASCADE, related_name="service_providers")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        """
        Returns a string representation of the service provider record.

        Returns:
            str: The unique identifier (ID) of the service provider record.
        """
        return str(self.id)


class UserServiceToken(models.Model):
    """
    Model representing a token associated with a user's service integration.

    Attributes:
        id (UUID): The unique identifier for the user service token.
        user (ForeignKey): The user associated with the service token.
        service (ForeignKey): The service associated with the token.
        access_token (str): The access token for authenticating the user to the service.
        refresh_token (str): The refresh token for obtaining a new access token.
        code (str): The authorization code for the service.
        created_at (datetime): The date and time when the token record was created.
        updated_at (datetime): The date and time when the token record was last updated.
        deleted_at (datetime): The date and time when the token record was deleted.
        initial_sync (bool): A flag indicating whether initial synchronization has occurred.
        last_sync_date (datetime): The date and time of the last synchronization.
        ongoing_sync_date (datetime): The date and time when the current synchronization started.
        sync_status (str): The status of the synchronization process, with choices defined in `STATUS_TYPE_CHOICES`.

    """
    STATUS_TYPE_CHOICES = (
        ('processing', 'processing'),
        ('completed', 'completed'),
        ('failed', 'failed')
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, related_name='user_service_tokens',
                             on_delete=models.CASCADE, null=True, blank=True)
    service = models.ForeignKey(
        Service,  on_delete=models.CASCADE, related_name="user_service_tokens")
    access_token = models.CharField(max_length=100, null=True, blank=True)
    refresh_token = models.CharField(max_length=100, null=True, blank=True)
    code = models.CharField(max_length=100, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    initial_sync = models.BooleanField(default=False)
    last_sync_date = models.DateTimeField(null=True, blank=True)
    ongoing_sync_date = models.DateTimeField(null=True, blank=True)
    sync_status = models.CharField(choices=STATUS_TYPE_CHOICES, max_length=100, default='processing')

    def __str__(self):
        """
        Returns a string representation of the user service token.

        Returns:
            str: The unique identifier (ID) of the user service token.
        """
        return str(self.id)


class Encounter(models.Model):
    """
    Model representing a healthcare encounter (e.g., visit, diagnosis, treatment) linked to a user.

    Attributes:
        id (UUID): The unique identifier for the encounter.
        ref_num (str, optional): The identifier of the encounter in the 1Up system.
        facility (str, optional): The name of the healthcare facility where the encounter took place.
        physician (str, optional): The name of the physician associated with the encounter.
        date_of_record (datetime, optional): The date and time when the encounter record was created.
        encounter_date (datetime, optional): The date and time when the encounter actually occurred.
        careplan (str, optional): The care plan associated with the encounter.
        condition (str, optional): The medical condition diagnosed during the encounter.
        code (str, optional): The code associated with the condition or procedure.
        record_number (str, optional): The unique record number for the encounter.
        diagnostic_report (str, optional): A report detailing the diagnosis for the encounter.
        medication_order (str, optional): The medication prescribed during the encounter.
        record_synced_at (datetime, optional): The date and time when the encounter record was synced from the 1Up API.
        user (ForeignKey, optional): The user associated with the encounter.
        created_at (datetime): The date and time when the encounter record was created.
        updated_at (datetime): The date and time when the encounter record was last updated.
        deleted_at (datetime, optional): The date and time when the encounter record was deleted.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ref_num = models.CharField(max_length=250, null=True, blank=True)# id of encounter in 1Up
    facility = models.CharField(max_length=250, null=True, blank=True)
    physician = models.CharField(max_length=80, null=True, blank=True)
    date_of_record = models.DateTimeField(null=True, blank=True)
    encounter_date = models.DateTimeField(null=True, blank=True)
    careplan = models.CharField(max_length=80, null=True, blank=True)
    condition = models.CharField(max_length=250, null=True, blank=True)
    code = models.CharField(max_length=80, null=True, blank=True)
    record_number = models.CharField(max_length=80, null=True, blank=True)
    diagnostic_report = models.CharField(max_length=250, null=True, blank=True)
    medication_order = models.CharField(max_length=250, null=True, blank=True)
    record_synced_at = models.DateTimeField(null=True, blank=True)# date from 1up api
    user = models.ForeignKey(User, related_name='encounters',
                             on_delete=models.CASCADE, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        """
        Returns a string representation of the encounter.

        Returns:
            str: The unique identifier (ID) of the encounter.
        """
        return str(self.id)


class Prescription(models.Model):
    """
    Model representing a prescription issued during a healthcare encounter.

    Attributes:
        id (UUID): The unique identifier for the prescription.
        ref_num (str, optional): The identifier of the prescription in the 1Up system.
        medication (str, optional): The name of the prescribed medication.
        active_substance (str, optional): The active ingredient(s) in the medication.
        prescribed_by (str, optional): The name of the healthcare provider who prescribed the medication.
        prescription_expiry (date, optional): The expiration date of the prescription.
        directions (str, optional): The directions for taking the prescribed medication.
        pharmacy (str, optional): The name of the pharmacy where the medication is prescribed to be filled.
        pharmacy_location (str, optional): The location of the pharmacy.
        allergy_intolerance (str, optional): Information about allergies or intolerances related to the prescription.
        is_self_created (bool, optional): A flag indicating whether the prescription was self-created (default is False).
        encounter (ForeignKey, optional): The healthcare encounter associated with the prescription.
        user (ForeignKey, optional): The user associated with the prescription.
        record_synced_at (datetime, optional): The date and time when the prescription record was synced from the 1Up API.
        created_at (datetime): The date and time when the prescription record was created.
        updated_at (datetime): The date and time when the prescription record was last updated.
        deleted_at (datetime, optional): The date and time when the prescription record was deleted.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ref_num = models.CharField(max_length=250, null=True, blank=True)# id of prescription in 1Up
    medication = models.CharField(max_length=250, null=True, blank=True)
    active_substance = models.CharField(max_length=250, null=True, blank=True)
    prescribed_by = models.CharField(max_length=250, null=True, blank=True)
    prescription_expiry = models.DateField(null=True, blank=True)
    directions = models.CharField(max_length=250, null=True, blank=True)
    pharmacy = models.CharField(max_length=250, null=True, blank=True)
    pharmacy_location = models.TextField(null=True, blank=True)
    allergy_intolerance = models.TextField(null=True, blank=True)
    is_self_created = models.BooleanField(default=False)
    encounter = models.ForeignKey(Encounter, related_name='prescriptions',
                                  on_delete=models.SET_NULL, null=True, blank=True)
    user = models.ForeignKey(User, related_name='prescriptions',
                             on_delete=models.CASCADE, null=True, blank=True)
    record_synced_at = models.DateTimeField(null=True, blank=True)# lastUpdated date from 1up api
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        """
        Returns a string representation of the prescription.

        Returns:
            str: The unique identifier (ID) of the prescription.
        """
        return str(self.id)


class Document(models.Model):
    """
    Model representing a medical or health-related document, such as test results, x-rays, or records.

    Attributes:
        id (UUID): The unique identifier for the document.
        category (str): The category of the document, chosen from predefined options such as 'Blood Results', 'X-Rays', etc.
        title (str): The title or name of the document.
        notes (str, optional): Additional notes or comments about the document.
        is_self_created (bool): A flag indicating whether the document was self-created (default is False).
        encounter (ForeignKey, optional): The healthcare encounter associated with the document.
        user (ForeignKey, optional): The user associated with the document.
        files (FileField, optional): The file associated with the document.
        file_name (str, optional): The name of the file associated with the document.
        record_synced_at (datetime, optional): The date and time when the document record was synced from the 1Up API.
        ref_num (str, optional): The reference number of the document in the 1Up system.
        created_at (datetime): The date and time when the document record was created.
        updated_at (datetime): The date and time when the document record was last updated.
        deleted_at (datetime, optional): The date and time when the document record was deleted, if applicable.

    """

    DOCUMENT_CHOICES = (
        ('blood_results', 'Blood Results'),
        ('x_rays', 'X-Rays'),
        ('imaging', 'Imaging'),
        ('lab_tests', 'Lab Tests'),
        ('vaccines', 'Vaccines'),
        ('fertility', 'Fertility'),
        ('genetics', 'Genetics'),
        ('others', 'Others'),
        ('synchronized', 'Synchronized Documents'),
    )
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    category = models.CharField(
        choices=DOCUMENT_CHOICES, default='synchronized')
    title = models.CharField(max_length=120)
    notes = models.TextField(null=True, blank=True)
    is_self_created = models.BooleanField(default=False)
    encounter = models.ForeignKey(Encounter, related_name='documents',
                                  on_delete=models.SET_NULL, null=True, blank=True)
    user = models.ForeignKey(User, related_name='documents',
                             on_delete=models.CASCADE, null=True, blank=True)
    files = models.FileField(upload_to=dynamic_upload_path, null=True)
    file_name = models.CharField(max_length=120, null=True)
    record_synced_at = models.DateTimeField(null=True, blank=True)# lastUpdated date from 1up api
    ref_num = models.CharField(max_length=250, null=True, blank=True)# id of document reference in 1Up
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        """
        Returns a string representation of the document.

        Returns:
            str: The title of the document.
        """
        return str(self.title)


class Condition(models.Model):
    """
    Model representing a health condition, such as a diagnosis or medical condition record.

    Attributes:
        id (UUID): The unique identifier for the condition.
        ref_num (str, optional): The reference number of the condition in the 1Up system.
        health_indicator (str, optional): A description or label of the health indicator associated with the condition.
        includes (str, optional): The details of what is included under the condition (e.g., related symptoms or conditions).
        diagnosis_code (str, optional): The code associated with the condition, often from a standardized medical coding system.
        encounter (ForeignKey, optional): The healthcare encounter during which the condition was diagnosed or observed.
        user (ForeignKey, optional): The user associated with the condition record.
        created_at (datetime): The date and time when the condition record was created.
        updated_at (datetime): The date and time when the condition record was last updated.
        deleted_at (datetime, optional): The date and time when the condition record was deleted, if applicable.
        record_synced_at (datetime, optional): The date and time when the condition record was synced from the 1Up API.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ref_num = models.CharField(max_length=250, null=True, blank=True)# id of condition in 1Up
    health_indicator = models.CharField(max_length=250, null=True, blank=True)
    includes = models.CharField(max_length=120, null=True, blank=True)
    diagnosis_code = models.CharField(max_length=120, null=True, blank=True)
    encounter = models.ForeignKey(Encounter, related_name='conditions',
                                  on_delete=models.SET_NULL, null=True, blank=True)
    user = models.ForeignKey(User, related_name='conditions',
                             on_delete=models.CASCADE, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    record_synced_at = models.DateTimeField(null=True, blank=True)# date from 1up api

    def __str__(self):
        """
        Returns a string representation of the condition.

        Returns:
            str: The unique identifier (ID) of the condition.
        """
        return str(self.id)
    

class Allergy(models.Model):
    """
    Model representing an allergy record associated with a user.

    Attributes:
        id (UUIDField): Unique identifier for the allergy record.
        type (CharField): Specifies the type of allergy.
        user (ForeignKey): Reference to the associated user.
        file (FileField): File attachment related to the allergy.
        file_name (CharField): Name of the uploaded file.
        created_at (DateTimeField): Timestamp of when the record was created.
        deleted_at (DateTimeField): Timestamp of when the record was deleted, if applicable.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    type = models.CharField(max_length=100)
    user = models.ForeignKey(User, related_name='allergies',
                             on_delete=models.CASCADE, null=True, blank=True)
    file = models.FileField(upload_to=dynamic_upload_path)
    file_name = models.CharField(max_length=120, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        """
        Returns a string representation of the condition.

        Returns:
            str: The unique identifier of the condition.
        """
        return str(self.id)


class Immunization(models.Model):
    """
    Model representing an immunization record for a user, typically including vaccine-related information.

    Attributes:
        id (UUID): The unique identifier for the immunization record.
        type (str): The type or name of the immunization (e.g., vaccine name).
        user (ForeignKey, optional): The user associated with the immunization record.
        file (FileField): The file associated with the immunization, typically containing documents or certificates.
        file_name (str, optional): The name of the uploaded file.
        created_at (datetime): The date and time when the immunization record was created.
        deleted_at (datetime, optional): The date and time when the immunization record was deleted, if applicable.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    type = models.CharField(max_length=100)
    user = models.ForeignKey(User, related_name='immunizations',
                             on_delete=models.CASCADE, null=True, blank=True)
    file = models.FileField(upload_to=dynamic_upload_path)
    file_name = models.CharField(max_length=120, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        """
        Returns a string representation of the immunization.

        Returns:
            str: The unique identifier of the immunization record.
        """
        return str(self.id)
    

class DataSyncLog(models.Model):
    """
    Model for tracking the synchronization logs of different resources (e.g., encounters, conditions, prescriptions, documents)
    associated with a user. This model helps monitor the progress, status, and error messages related to data synchronization tasks.

    Attributes:
        RESOURCE_TYPE_CHOICES (tuple): A list of possible resource types being synchronized.
        STATUS_TYPE_CHOICES (tuple): A list of possible synchronization statuses (e.g., processing, completed, failed).
        SYNC_TYPE_CHOICES (tuple): A list of possible sync types (e.g., initial or refresh).

        resource (str): The type of resource being synchronized (e.g., encounter, condition, prescription, document).
        user_service_id (str): The identifier for the user service associated with the synchronization task.
        user (str): The user who initiated the sync process.
        task_id (str): The unique task identifier associated with the synchronization.
        is_complete (bool): A flag indicating whether the sync task is complete.
        error_msg (JSONField, optional): A JSON object storing error messages if the synchronization fails.
        created_at (datetime): The timestamp when the sync log entry was created.
        updated_at (datetime): The timestamp when the sync log entry was last updated.
        no_of_records (int): The total number of records involved in the sync process.
        completed_page_count (int): The number of pages successfully processed so far.
        total_page_count (int): The total number of pages to be processed in the sync task.
        sync_type (str): The type of synchronization (e.g., initial or refresh).
        status (str): The current status of the sync task (e.g., processing, completed, failed).
        payload (JSONField, optional): A JSON object holding additional data related to the sync process.
    """
    RESOURCE_TYPE_CHOICES = (
        ('encounter', 'encounter'),
        ('condition', 'condition'),
        ('prescription', 'prescription'),
        ('document', 'document')
    )

    STATUS_TYPE_CHOICES = (
        ('processing', 'processing'),
        ('completed', 'completed'),
        ('failed', 'failed')
    )
    
    SYNC_TYPE_CHOICES = (
        ('initial', 'initial'),
        ('refresh', 'refresh')
    )

    resource = models.CharField(choices=RESOURCE_TYPE_CHOICES, max_length=100)
    user_service_id = models.CharField(max_length=150)
    user = models.CharField(max_length=150)
    task_id = models.CharField(max_length=150)
    is_complete = models.BooleanField(default=False)
    error_msg = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    no_of_records = models.IntegerField(default=0)
    completed_page_count = models.IntegerField(default=0)
    total_page_count = models.IntegerField(default=0)
    sync_type = models.CharField(choices=SYNC_TYPE_CHOICES, max_length=100, default='initial')
    status = models.CharField(choices=STATUS_TYPE_CHOICES, max_length=100, default='processing')
    payload = models.JSONField(null=True, blank=True)

    def __str__(self):
        """
        Returns a string representation of the DataSyncLog.

        Returns:
            str: The unique identifier of the sync log.
        """
        return str(self.id)


class CeleryTaskmeta(models.Model):
    """
    Model for storing metadata of Celery tasks. This model holds information about the execution
    status, results, and related task details, allowing tracking and debugging of Celery task executions.

    Attributes:
        id (int): The primary key for the task metadata record.
        task_id (str, optional): The unique identifier for the Celery task.
        status (str, optional): The status of the Celery task (e.g., 'SUCCESS', 'FAILURE').
        result (BinaryField, optional): The result of the Celery task execution, stored as binary data.
        date_done (datetime, optional): The timestamp when the task execution was completed.
        traceback (str, optional): A traceback of any error that occurred during task execution.
        name (str, optional): The name of the Celery task.
        args (BinaryField, optional): The arguments passed to the task, stored as binary data.
        kwargs (BinaryField, optional): The keyword arguments passed to the task, stored as binary data.
        worker (str, optional): The name of the worker that executed the task.
        retries (int, optional): The number of retries the task has undergone.
        queue (str, optional): The name of the Celery queue the task was assigned to.

    Meta:
        managed (bool): Set to False because this model is mapped to an existing database table managed by Celery.
        db_table (str): The name of the database table (`celery_taskmeta`) that stores the task metadata.
    """
    id = models.IntegerField(primary_key=True)
    task_id = models.CharField(unique=True, max_length=155, blank=True, null=True)
    status = models.CharField(max_length=50, blank=True, null=True)
    result = models.BinaryField(blank=True, null=True)
    date_done = models.DateTimeField(blank=True, null=True)
    traceback = models.TextField(blank=True, null=True)
    name = models.CharField(max_length=155, blank=True, null=True)
    args = models.BinaryField(blank=True, null=True)
    kwargs = models.BinaryField(blank=True, null=True)
    worker = models.CharField(max_length=155, blank=True, null=True)
    retries = models.IntegerField(blank=True, null=True)
    queue = models.CharField(max_length=155, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'celery_taskmeta'


class DataSyncExceptionLog(models.Model):
    """
    Model for logging exceptions related to data synchronization tasks. This model is used to 
    store details about exceptions that occur during the synchronization process, including the 
    associated task ID and the payload that was processed at the time of the exception.

    Attributes:
        task_id (str): The unique identifier of the synchronization task that encountered an exception.
        payload (JSONField): A JSON object that stores the data associated with the task at the time of the exception.
        created_at (datetime): The timestamp when the exception was logged.

    """
    task_id = models.CharField(max_length=150)
    payload = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        """
        Returns a string representation of the exception log, including the task ID and the timestamp when the log was created.

        Returns:
            str: A description of the exception log with the task ID and creation time.
        """
        return f"Task {self.task_id} logged at {self.created_at}"


class ExternalAPILog(models.Model):
    """
    Model for logging details of external API requests made by users. This model captures key 
    information about each API call, including the user making the request, the API endpoint, 
    whether the request was successful, and any error messages encountered.

    Attributes:
        id (UUIDField): A unique identifier for the API log entry.
        user_service (ForeignKey): A reference to the `UserServiceToken` that the user is using to make the API request.
        user (ForeignKey): A reference to the `User` who initiated the API request.
        api_endpoint (TextField): The URL or endpoint of the external API that was called.
        requested_at (DateTimeField): The timestamp when the API request was made.
        is_success_response (BooleanField): A flag indicating whether the API request was successful. Defaults to `True`.
        error_message (JSONField): A JSON object containing error details if the API request failed. Null if no errors occurred.
        is_initial_sync (BooleanField): A flag indicating whether this log entry corresponds to the initial sync. Defaults to `True`.

    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_service = models.ForeignKey(
        UserServiceToken,  on_delete=models.CASCADE, related_name="external_api_log")
    user = models.ForeignKey(
        User,  on_delete=models.CASCADE, related_name="external_api_log")
    api_endpoint = models.TextField(null=True, blank=True)
    requested_at = models.DateTimeField(auto_now_add=True)
    is_success_response = models.BooleanField(default=True)
    error_message = models.JSONField(null=True, blank=True)
    is_initial_sync = models.BooleanField(default=True)

    def __str__(self):
        """
        Returns a string representation of the API log entry, including the API endpoint and the user ID.

        Returns:
            str: A description of the API log with the API endpoint and the user ID.
        """
        return f"API Log: {self.api_endpoint} - User: {self.user.id}"

class EvexiaMenu(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    product_id = models.IntegerField(null=True, blank=True)
    product_name = models.CharField(max_length=255, null=True, blank=True)
    lab_id = models.IntegerField(null=True, blank=True)
    is_panel = models.BooleanField(default=False)
    sales_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    test_code = models.CharField(max_length=100, null=True, blank=True)
    is_kit = models.BooleanField(default=False)
    lab_name = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)

    class Meta:
        db_table = 'health_evexia_menu'  # Custom table name


class EvexiaPatient(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    patient_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    external_client_id = models.UUIDField(null=True, blank=True)
    user_id = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'health_evexia_patient'

    def __str__(self):
        return f"Patient {self.patient_id} (External ID: {self.external_client_id})"



class EvexiaOrders(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    patient_id = models.CharField(max_length=255, null=True, blank=True)
    patient_order_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    product_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    documents = models.FileField(upload_to='receipts/', null=True, blank=True)
    payment_status = models.CharField(max_length=255, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'health_evexia_orders'

    def __str__(self):
        return f"Patient {self.patient_id} (Order ID: {self.patient_order_id})"


class EvexiaPayment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    patient_id = models.CharField(max_length=255, null=True, blank=True)
    payment_id = models.CharField(max_length=255, null=True, blank=True) 
    patient_order_id = models.CharField(max_length=255, null=True, blank=True) 
    total_amount = models.DecimalField(
        max_digits=10, 
        decimal_places=2, 
        null=False, 
        blank=False, 
        help_text="Total amount for the payment in USD or applicable currency."
    )
    payment_status = models.CharField(
        max_length=50,  # You can adjust the length as per your requirements
        null=False, 
        blank=False, 
        help_text="Payment status (e.g., succeeded, failed, pending)."
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'health_evexia_payments'
        verbose_name = 'Evexia Order Payment'
        verbose_name_plural = 'Evexia Order Payments'

    def __str__(self):
        return f"Patient {self.patient_id} - Order {self.id} - Status: {self.payment_status}"
