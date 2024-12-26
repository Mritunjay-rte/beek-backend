from django.db import models
import uuid
from user.models import User

class EncounterBulkExport(models.Model):
    """
    Model for storing bulk export data related to patient encounters. This model captures various 
    details about an encounter, including identifiers, periods, hospitalizations, and service provider information.

    Attributes:
        id (UUIDField): A unique identifier for the encounter bulk export record.
        identifier (JSONField): A JSON object containing identifiers for the encounter.
        period_start (CharField): The start date of the encounter period.
        period_end (CharField): The end date of the encounter period.
        hospitalization (JSONField): Details about the hospitalization related to the encounter.
        subject_reference (CharField): Reference to the subject of the encounter.
        subject_display (CharField): Display name for the subject.
        appointment (JSONField): Information about the appointment associated with the encounter.
        type (JSONField): Type of encounter
        meta_last_updated (CharField): Timestamp of the last update to the metadata.
        meta_version_id (CharField): Version ID of the encounter metadata.
        service_provider_ref (CharField): Reference to the service provider for the encounter.
        service_provider_display (CharField): Display name for the service provider.
        location (JSONField): Information about the location where the encounter occurred.
        ref_num (CharField): Reference number for the encounter.
        reason_code (JSONField): Reason codes associated with the encounter.
        text (JSONField): Textual representation of the encounter.
        status (CharField): The status of the encounter.
        encounter_class (JSONField): Class of the encounter.
        user (ForeignKey): The user who initiated the encounter export record.
        extension (JSONField): Additional extension data for the encounter.
        participant (JSONField): Information about participants involved in the encounter (e.g., practitioners, relatives).
        priority (JSONField): Priority of the encounter.
        account (JSONField): Related account information for the encounter.
        raw_data (JSONField): Complete raw data payload of the encounter.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    identifier = models.JSONField(null=True, blank=True)
    period_start = models.CharField(null=True, blank=True)
    period_end = models.CharField(null=True, blank=True)
    hospitalization = models.JSONField(null=True, blank=True)
    subject_reference = models.CharField(null=True, blank=True)
    subject_display = models.CharField(null=True, blank=True)
    appointment = models.JSONField(null=True, blank=True)
    type = models.JSONField(null=True, blank=True)
    meta_last_updated = models.CharField(null=True, blank=True)
    meta_version_id = models.CharField(null=True, blank=True)
    service_provider_ref = models.CharField(null=True, blank=True)
    service_provider_display = models.CharField(null=True, blank=True)
    location = models.JSONField(null=True, blank=True)
    ref_num = models.CharField(null=True, blank=True)
    reason_code = models.JSONField(null=True, blank=True)
    text = models.JSONField(null=True, blank=True)
    status = models.CharField(null=True, blank=True)
    encounter_class = models.JSONField(null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    extension = models.JSONField(null=True, blank=True)
    participant = models.JSONField(null=True, blank=True)
    priority = models.JSONField(null=True, blank=True)
    account = models.JSONField(null=True, blank=True)
    raw_data = models.JSONField(null=True, blank=True)


    def __str__(self):
        """
        Returns a string representation of the encounter bulk export record, including the ID.

        Returns:
            str: The unique identifier (ID) of encounter bulk export record.
        """
        return str(self.id)
    


class ConditionBulkExport(models.Model):
    """
    Model for storing bulk export data related to patient conditions. This model captures various 
    details about a condition, including identifiers, codes, verification status, and encounter information.

    Attributes:
        id (UUIDField): A unique identifier for the condition bulk export record.
        identifier (JSONField): A JSON object containing identifiers for the condition.
        code (JSONField): Codes associated with the condition.
        verification_status (JSONField): Verification status of the condition.
        subject_reference (CharField): Reference to the subject of the condition.
        subject_display (CharField): Display name for the subject.
        meta_last_updated (CharField): Timestamp of the last update to the metadata.
        meta_version_id (CharField): Version ID of the condition metadata.
        ref_num (CharField): Reference number for the condition.
        text (JSONField): Textual representation of the condition.
        category (JSONField): Category of the condition.
        user (ForeignKey): The user who initiated the condition export record.
        extension (JSONField): Additional extension data for the condition.
        recorded_date (CharField): Date when the condition was recorded.
        encounter (ForeignKey): The encounter associated with the condition (optional).
        encounter_ref (CharField): Reference to the encounter associated with the condition.
        clinical_status (JSONField): Current clinical status of the condition (e.g., active, resolved).
        abatement_date_time (CharField): Date or timestamp when the condition abated (resolved or ended).
        raw_data (JSONField): Complete raw data payload of the condition.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    identifier = models.JSONField(null=True, blank=True)
    code = models.JSONField(null=True, blank=True)
    verification_status = models.JSONField(null=True, blank=True)
    subject_reference = models.CharField(null=True, blank=True)
    subject_display = models.CharField(null=True, blank=True)
    meta_last_updated = models.CharField(null=True, blank=True)
    meta_version_id = models.CharField(null=True, blank=True)
    ref_num = models.CharField(null=True, blank=True)
    text = models.JSONField(null=True, blank=True)
    category = models.JSONField(null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    extension = models.JSONField(null=True, blank=True)
    recorded_date = models.CharField(null=True, blank=True)
    encounter = models.ForeignKey(EncounterBulkExport, null=True, blank=True, on_delete=models.CASCADE)
    encounter_ref = models.CharField(null=True, blank=True)
    clinical_status = models.JSONField(null=True, blank=True)
    abatement_date_time = models.CharField(null=True, blank=True)
    raw_data = models.JSONField(null=True, blank=True)

    def __str__(self):
        """
        Returns a string representation of the condition bulk export record, including the ID.

        Returns:
            str: The unique identifier (ID) of condition bulk export record.
        """
        return str(self.id)
    

class DocumentReferenceBulkExport(models.Model):
    """
    Model for storing bulk export data related to document references. This model captures various details 
    about document references, including metadata, author information, and encounter data, structured for 
    bulk export.

    Attributes:
        id (UUIDField): A unique identifier for the document reference bulk export record.
        date (CharField): Date associated with the document reference.
        subject_reference (CharField): Reference to the subject of the document.
        subject_display (CharField): Display name for the subject.
        type (JSONField): Type of the document reference.
        content (JSONField): Content of the document, typically a list of sections or parts.
        doc_status (CharField): Status of the document.
        context_period_start (CharField): Start date of the document context period.
        context_period_end (CharField): End date of the document context period.
        encounter (ForeignKey): The encounter associated with the document reference (optional).
        encounter_ref (CharField): Reference to the encounter associated with the document.
        ref_num (CharField): Reference number for the document.
        text (JSONField): Textual representation of the document reference.
        authenticator_reference (CharField): Reference to the authenticator of the document.
        authenticator_display (CharField): Display name for the authenticator.
        custodian_reference (CharField): Reference to the custodian of the document.
        custodian_display (CharField): Display name for the custodian.
        author_reference (CharField): Reference to the author of the document.
        author_display (CharField): Display name for the author.
        identifier (JSONField): Identifiers associated with the document reference.
        category (JSONField): Category of the document reference.
        meta_last_updated (CharField): Timestamp of the last update to the metadata.
        meta_version_id (CharField): Version ID of the document reference metadata.
        status (CharField): Status of the document.
        user (ForeignKey): The user who initiated the document reference export record.
        raw_data (JSONField): Complete raw data payload of the document reference.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    date = models.CharField(null=True, blank=True)
    subject_reference = models.CharField(null=True, blank=True)
    subject_display = models.CharField(null=True, blank=True)
    type = models.JSONField(null=True, blank=True)
    content = models.JSONField(null=True, blank=True)
    doc_status = models.CharField(null=True, blank=True)
    context_period_start = models.CharField(null=True, blank=True)
    context_period_end = models.CharField(null=True, blank=True)
    encounter = models.ForeignKey(EncounterBulkExport, null=True, blank=True, on_delete=models.CASCADE)
    encounter_ref = models.CharField(null=True, blank=True)
    ref_num = models.CharField(null=True, blank=True)
    text = models.JSONField(null=True, blank=True)
    authenticator_reference = models.CharField(null=True, blank=True)
    authenticator_display = models.CharField(null=True, blank=True)
    custodian_reference = models.CharField(null=True, blank=True)
    custodian_display = models.CharField(null=True, blank=True)
    author_reference = models.CharField(null=True, blank=True)
    author_display = models.CharField(null=True, blank=True)
    identifier = models.JSONField(null=True, blank=True)
    category = models.JSONField(null=True, blank=True)
    meta_last_updated = models.CharField(null=True, blank=True)
    meta_version_id = models.CharField(null=True, blank=True)
    status = models.CharField(null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    raw_data = models.JSONField(null=True, blank=True)

    def __str__(self):
        """
        Returns a string representation of the document reference bulk export record, including the ID.

        Returns:
            str: The unique identifier (ID) of document reference bulk export.
        """
        return str(self.id)


class MedicationRequestBulkExport(models.Model):
    """
    Model for storing bulk export data related to medication requests. This model captures various details 
    about medication requests, including the patient, medication details, dispensing instructions, and status, 
    structured for bulk export and integration with other systems.

    Attributes:
        id (UUIDField): A unique identifier for the medication request bulk export record.
        extension (JSONField): Additional information or extensions related to the medication request.
        substitution (JSONField): Information regarding any substitution for the medication.
        course_of_therapy_type (JSONField): The type of course for the therapy.
        subject_reference (CharField): Reference to the subject of the medication request.
        subject_display (CharField): Display name for the subject.
        dispense_request (JSONField): Request details for dispensing the medication.
        ref_num (CharField): Reference number for the medication request.
        text (JSONField): Textual representation of the medication request.
        requester_reference (CharField): Reference to the requester.
        requester_display (CharField): Display name for the requester.
        identifier (JSONField): Identifiers associated with the medication request.
        reported_boolean (BooleanField): Boolean flag indicating whether the medication request is reported.
        authored_on (CharField): Date or timestamp when the medication request was authored.
        encounter (ForeignKey): The encounter associated with the medication request (optional).
        encounter_ref (CharField): Reference to the encounter associated with the medication request.
        medication_codeable_concept (JSONField): Codeable concept for the medication requested.
        dosage_instruction (JSONField): Instructions for dosing the medication.
        meta_last_updated (CharField): Timestamp of the last update to the metadata.
        meta_version_id (CharField): Version ID of the medication request metadata.
        category (JSONField): Category of the medication request.
        status (CharField): Status of the medication request.
        user (ForeignKey): The user who initiated the medication request export record.
        recorder (JSONField): Information about the person or device recording the medication request.
        reason_code (JSONField): Reasons or codes for why the medication request was made.
        medication_reference (JSONField): Reference to the medication being requested.
        intent (CharField): Intent of the medication request (e.g., proposal, plan, order).
        raw_data (JSONField): Complete raw data payload of the medication request.

    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    extension = models.JSONField(null=True, blank=True)
    substitution = models.JSONField(null=True, blank=True)
    course_of_therapy_type = models.JSONField(null=True, blank=True)
    subject_reference = models.CharField(null=True, blank=True)
    subject_display = models.CharField(null=True, blank=True)
    dispense_request = models.JSONField(null=True, blank=True)
    ref_num = models.CharField(null=True, blank=True)
    text = models.JSONField(null=True, blank=True)
    requester_reference = models.CharField(null=True, blank=True)
    requester_display = models.CharField(null=True, blank=True)
    identifier = models.JSONField(null=True, blank=True)
    reported_boolean = models.BooleanField(default=False)
    authored_on = models.CharField(null=True, blank=True)
    encounter = models.ForeignKey(EncounterBulkExport, null=True, blank=True, on_delete=models.CASCADE)
    encounter_ref = models.CharField(null=True, blank=True)
    medication_codeable_concept = models.JSONField(null=True, blank=True)
    dosage_instruction = models.JSONField(null=True, blank=True)
    meta_last_updated = models.CharField(null=True, blank=True)
    meta_version_id = models.CharField(null=True, blank=True)
    category = models.JSONField(null=True, blank=True)
    status = models.CharField(null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    recorder = models.JSONField(null=True, blank=True)
    reason_code = models.JSONField(null=True, blank=True)
    medication_reference = models.JSONField(null=True, blank=True)
    intent = models.CharField(null=True, blank=True)
    raw_data = models.JSONField(null=True, blank=True)

    def __str__(self):
        """
        Returns a string representation of the medication request bulk export record, including the ID.

        Returns:
            str: The unique identifier (ID) of medication request bulk export record.
        """
        return str(self.id)
