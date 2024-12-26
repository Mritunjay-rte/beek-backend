from bulk_export.models import EncounterBulkExport, ConditionBulkExport, DocumentReferenceBulkExport, MedicationRequestBulkExport
from django.db import transaction
import time


def save_encounter_bulk_export(data, encounter_ids, user_service):
    """
    Save bulk exported encounter data to the database.

    This function processes and stores bulk encounter data for a specific user.

    Args:
        data (dict): The bulk encounter data to be saved. Typically, this is a dictionary
            containing details about encounters, their attributes, and related information.
        encounter_ids (list): A list of unique identifiers for the encounters to be saved.
        user_service (UserServiceToken): The user service instance associated with the encounter data.

    Returns:
        None
    """

    updated_encounters = []
    encounter_details = []
    lst_updated_ref_num = []
    lst_created_ref_num = []

    existing_encounters = EncounterBulkExport.objects.filter(ref_num__in=encounter_ids, user=user_service.user).only('ref_num')
    existing_encounters_map = {enc.ref_num: enc for enc in existing_encounters}
    try:
        with transaction.atomic():
            for encounter_data in data:
                ref_num = encounter_data.get('id')
                existing_encounter = existing_encounters_map.get(ref_num)

                if existing_encounter:
                    # Update existing encounter with new data from encounter_data
                    existing_encounter.identifier = encounter_data.get("identifier")
                    existing_encounter.period_start = encounter_data.get("period", {}).get("start")
                    existing_encounter.period_end = encounter_data.get("period", {}).get("end")
                    existing_encounter.hospitalization = encounter_data.get("hospitalization")
                    existing_encounter.subject_reference = encounter_data.get("serviceProvider", {}).get("reference")
                    existing_encounter.subject_display = encounter_data.get("serviceProvider", {}).get("display")
                    existing_encounter.appointment = encounter_data.get("appointment")
                    existing_encounter.type = encounter_data.get("type")
                    existing_encounter.meta_last_updated = encounter_data.get("meta", {}).get("lastUpdated")
                    existing_encounter.meta_version_id = encounter_data.get("meta", {}).get("versionId")
                    existing_encounter.service_provider_ref = encounter_data.get("serviceProvider", {}).get("reference")
                    existing_encounter.service_provider_display = encounter_data.get("serviceProvider", {}).get("display")
                    existing_encounter.location = encounter_data.get("location")
                    existing_encounter.ref_num = encounter_data.get("id")
                    existing_encounter.reason_code = encounter_data.get("reasonCode")
                    existing_encounter.text = encounter_data.get("text")
                    existing_encounter.status = encounter_data.get("status")
                    existing_encounter.encounter_class = encounter_data.get("class")
                    existing_encounter.extension = encounter_data.get("extension")
                    existing_encounter.priority = encounter_data.get("priority")
                    existing_encounter.participant = encounter_data.get("participant")
                    existing_encounter.account = encounter_data.get("account")
                    existing_encounter.raw_data = encounter_data

                    # Append to updated encounters list
                    updated_encounters.append(existing_encounter)
                    lst_updated_ref_num.append(existing_encounter.ref_num)

                else:
                    # Create a new encounter with provided data
                    new_encounter = EncounterBulkExport(
                        identifier=encounter_data.get("identifier"),
                        period_start=encounter_data.get("period", {}).get("start"),
                        period_end=encounter_data.get("period", {}).get("end"),
                        hospitalization=encounter_data.get("hospitalization"),
                        subject_reference=encounter_data.get("serviceProvider", {}).get("reference"),
                        subject_display=encounter_data.get("serviceProvider", {}).get("display"),
                        appointment=encounter_data.get("appointment"),
                        type=encounter_data.get("type"),
                        meta_last_updated=encounter_data.get("meta", {}).get("lastUpdated"),
                        meta_version_id=encounter_data.get("meta", {}).get("versionId"),
                        service_provider_ref=encounter_data.get("serviceProvider", {}).get("reference"),
                        service_provider_display=encounter_data.get("serviceProvider", {}).get("display"),
                        location=encounter_data.get("location"),
                        ref_num=encounter_data.get("id"),
                        reason_code=encounter_data.get("reasonCode"),
                        text=encounter_data.get("text"),
                        status=encounter_data.get("status"),
                        encounter_class=encounter_data.get("class"),
                        user=user_service.user,
                        extension=encounter_data.get("extension", {}),
                        priority=encounter_data.get("priority", {}),
                        participant=encounter_data.get("participant", {}),
                        account=encounter_data.get("account", {}),
                        raw_data=encounter_data
                    )

                    # Append to created encounters list
                    encounter_details.append(new_encounter)
                    lst_created_ref_num.append(new_encounter.ref_num)


            def apply_post_save_updates():
                for instance in encounter_details + updated_encounters:
                    ConditionBulkExport.objects.filter(encounter_ref=instance.ref_num, encounter__isnull=True).update(encounter=instance)
                    DocumentReferenceBulkExport.objects.filter(encounter_ref=instance.ref_num, encounter__isnull=True).update(encounter=instance)
                    MedicationRequestBulkExport.objects.filter(encounter_ref=instance.ref_num, encounter__isnull=True).update(encounter=instance)


            if encounter_details:
                try:
                    EncounterBulkExport.objects.bulk_create(encounter_details)     
                except Exception as e:
                    print(str(e))
    
    
            if updated_encounters:
                try:
                    EncounterBulkExport.objects.bulk_update(
                        updated_encounters,
                        [ "identifier", "period_start", "period_end", "hospitalization", "subject_reference", "subject_display", "appointment", 
                          "type", "meta_last_updated", "meta_version_id", "service_provider_ref", "service_provider_display", "location", "ref_num",
                          "reason_code", "text", "status", "encounter_class", "extension" , "priority", "participant", "account", "raw_data"]
                    )
                except Exception as e:
                    print(str(e))

            transaction.on_commit(apply_post_save_updates)

        print("completed bulk export")
    except Exception as e:
        print(f"Error saving EncounterBulkExport: {e}")



def save_condition_bulk_export(data, condition_ids, user_service):
    """
    Save bulk exported condition data to the database.

    This function processes and stores bulk condition data for a specific user.

    Args:
        data (dict): The bulk condition data to be saved. Typically, this is a dictionary
            containing details about conditions, their attributes, and related information.
        condition_ids (list): A list of unique identifiers for the conditions to be saved.
        user_service (UserServiceToken): The user service instance associated with the condition data.
        
    Returns:
        None
    """

    updated_conditions = []
    condition_details = []
    lst_updated_ref_num = []
    lst_created_ref_num = []

    # Fetch existing conditions based on ref_num and user
    existing_conditions = ConditionBulkExport.objects.filter(ref_num__in=condition_ids, user=user_service.user).only('ref_num')
    existing_conditions_map = {cond.ref_num: cond for cond in existing_conditions}

    user_encounters = EncounterBulkExport.objects.filter(user=user_service.user).only('ref_num')
    user_encounters_map = {enc.ref_num: enc for enc in user_encounters}


    
    try:
        with transaction.atomic():
            for condition_data in data:
                ref_num = condition_data.get('id')

                existing_condition = existing_conditions_map.get(ref_num)

                encounter_ref = condition_data.get("encounter", {}).get("reference").split('/')[1] if condition_data.get("encounter", {}).get("reference") else None
                encounter_obj = user_encounters_map.get(encounter_ref)

                if existing_condition:
                    # Update existing condition with new data from condition_data
                    existing_condition.identifier = condition_data.get("identifier")
                    existing_condition.code = condition_data.get("code")
                    existing_condition.verification_status = condition_data.get("verificationStatus")
                    existing_condition.subject_reference = condition_data.get("subject", {}).get("reference")
                    existing_condition.subject_display = condition_data.get("subject", {}).get("display")
                    existing_condition.meta_last_updated = condition_data.get("meta", {}).get("lastUpdated")
                    existing_condition.meta_version_id = condition_data.get("meta", {}).get("versionId")
                    existing_condition.ref_num = condition_data.get("id")
                    existing_condition.text = condition_data.get("text")
                    existing_condition.category = condition_data.get("category")
                    existing_condition.extension = condition_data.get("extension")
                    existing_condition.recorded_date = condition_data.get("recordedDate")
                    existing_condition.encounter_ref = encounter_ref
                    existing_condition.encounter=encounter_obj
                    existing_condition.clinical_status=condition_data.get("clinicalStatus")
                    existing_condition.abatement_date_time=condition_data.get("abatementDateTime")
                    existing_condition.raw_data=condition_data

                    # Append to updated conditions list
                    updated_conditions.append(existing_condition)
                    lst_updated_ref_num.append(existing_condition.ref_num)

                else:
                    # Create a new condition with provided data
                    new_condition = ConditionBulkExport(
                        identifier=condition_data.get("identifier"),
                        code=condition_data.get("code"),
                        verification_status=condition_data.get("verificationStatus"),
                        subject_reference=condition_data.get("subject", {}).get("reference"),
                        subject_display=condition_data.get("subject", {}).get("display"),
                        meta_last_updated=condition_data.get("meta", {}).get("lastUpdated"),
                        meta_version_id=condition_data.get("meta", {}).get("versionId"),
                        ref_num=condition_data.get("id"),
                        text=condition_data.get("text"),
                        category=condition_data.get("category"),
                        user=user_service.user,
                        extension=condition_data.get("extension"),
                        recorded_date=condition_data.get("recordedDate"),
                        encounter_ref=encounter_ref,
                        encounter=encounter_obj,
                        clinical_status=condition_data.get("clinicalStatus"),
                        abatement_date_time=condition_data.get("abatementDateTime"),
                        raw_data=condition_data
                    )

                    # Append to created conditions list
                    condition_details.append(new_condition)
                    lst_created_ref_num.append(new_condition.ref_num)

            # Bulk create new conditions
            if condition_details:
                try:
                    ConditionBulkExport.objects.bulk_create(condition_details)
                except Exception as e:
                    print("Error during bulk_create:", str(e))
    
            # Bulk update existing conditions
            if updated_conditions:
                try:
                    ConditionBulkExport.objects.bulk_update(
                        updated_conditions,
                        ["identifier", "code", "verification_status", "subject_reference", 
                         "subject_display", "meta_last_updated", "meta_version_id", "ref_num", 
                         "text", "category", "extension", "recorded_date", "encounter_ref", 
                         "encounter", "clinical_status", "abatement_date_time", "raw_data"]
                    )
                except Exception as e:
                    print("Error during bulk_update:", str(e))

        print("Condition bulk export completed")
    except Exception as e:
        print(f"Error saving ConditionBulkExport: {e}")



def save_document_reference_bulk_export(data, document_ids, user_service):
    """
    Save bulk exported document data to the database.

    This function processes and stores bulk document data for a specific user.

    Args:
        data (dict): The bulk document data to be saved. Typically, this is a dictionary
            containing details about documents, their attributes, and related information.
        document_ids (list): A list of unique identifiers for the documents to be saved.
        user_service (UserServiceToken): The user service instance associated with the document data.
        
    Returns:
        None
    """
    updated_documents = []
    document_details = []
    lst_updated_ref_num = []
    lst_created_ref_num = []

    # Fetch existing document references based on ref_num and user
    existing_documents = DocumentReferenceBulkExport.objects.filter(ref_num__in=document_ids, user=user_service.user).only('ref_num')
    existing_documents_map = {doc.ref_num: doc for doc in existing_documents}

    user_encounters = EncounterBulkExport.objects.filter(user=user_service.user).only('ref_num')
    user_encounters_map = {enc.ref_num: enc for enc in user_encounters}

    
    try:
        with transaction.atomic():
            for document_data in data:
                ref_num = document_data.get('id')
                existing_document = existing_documents_map.get(ref_num)

                encounter_ref = document_data.get("context", {}).get("encounter", [{}])[0].get("reference").split('/')[1] if document_data.get("context", {}).get("encounter", [{}])[0].get("reference") else None
                encounter_obj = user_encounters_map.get(encounter_ref)

                if existing_document:
                    # Update existing document reference with new data from document_data
                    existing_document.date = document_data.get("date")
                    existing_document.subject_reference = document_data.get("subject", {}).get("reference")
                    existing_document.subject_display = document_data.get("subject", {}).get("display")
                    existing_document.type = document_data.get("type")
                    existing_document.content = document_data.get("content")
                    existing_document.doc_status = document_data.get("docStatus")
                    existing_document.context_period_start = document_data.get("context", {}).get("period", {}).get("start")
                    existing_document.context_period_end = document_data.get("context", {}).get("period", {}).get("end") 
                    existing_document.encounter_ref = encounter_ref
                    existing_document.encounter = encounter_obj
                    existing_document.ref_num = document_data.get("id")
                    existing_document.text = document_data.get("text")
                    existing_document.authenticator_reference = document_data.get("authenticator", {}).get("reference")
                    existing_document.authenticator_display = document_data.get("authenticator", {}).get("display")
                    existing_document.custodian_reference = document_data.get("custodian", {}).get("reference")
                    existing_document.custodian_display = document_data.get("custodian", {}).get("display")
                    existing_document.author_reference = document_data.get("author", [{}])[0].get("reference")
                    existing_document.author_display = document_data.get("author", [{}])[0].get("display")
                    existing_document.identifier = document_data.get("identifier")
                    existing_document.category = document_data.get("category")
                    existing_document.meta_last_updated = document_data.get("meta", {}).get("lastUpdated")
                    existing_document.meta_version_id = document_data.get("meta", {}).get("versionId")
                    existing_document.status = document_data.get("status")
                    existing_document.raw_data = document_data

                    # Append to updated documents list
                    updated_documents.append(existing_document)
                    lst_updated_ref_num.append(existing_document.ref_num)

                else:
                    # Create a new document reference with provided data
                    new_document = DocumentReferenceBulkExport(
                        date=document_data.get("date"),
                        subject_reference=document_data.get("subject", {}).get("reference"),
                        subject_display=document_data.get("subject", {}).get("display"),
                        type=document_data.get("type"),
                        content=document_data.get("content"),
                        doc_status=document_data.get("docStatus"),
                        context_period_start=document_data.get("context", {}).get("period", {}).get("start"),
                        context_period_end=document_data.get("context", {}).get("period", {}).get("end"),
                        encounter_ref = encounter_ref,
                        encounter = encounter_obj,
                        ref_num=document_data.get("id"),
                        text=document_data.get("text"),
                        authenticator_reference=document_data.get("authenticator", {}).get("reference"),
                        authenticator_display=document_data.get("authenticator", {}).get("display"),
                        custodian_reference=document_data.get("custodian", {}).get("reference"),
                        custodian_display=document_data.get("custodian", {}).get("display"),
                        author_reference=document_data.get("author", [{}])[0].get("reference"),
                        author_display=document_data.get("author", [{}])[0].get("display"),
                        identifier=document_data.get("identifier"),
                        category=document_data.get("category"),
                        meta_last_updated=document_data.get("meta", {}).get("lastUpdated"),
                        meta_version_id=document_data.get("meta", {}).get("versionId"),
                        status=document_data.get("status"),
                        user=user_service.user,
                        raw_data=document_data
                    )

                    # Append to created documents list
                    document_details.append(new_document)
                    lst_created_ref_num.append(new_document.ref_num)

            # Bulk create new documents
            if document_details:
                try:
                    DocumentReferenceBulkExport.objects.bulk_create(document_details)
                except Exception as e:
                    print("Error during bulk_create:", str(e))
    
            # Bulk update existing documents
            if updated_documents:
                try:
                    DocumentReferenceBulkExport.objects.bulk_update(
                        updated_documents,
                        ["date", "subject_reference", "subject_display", "type", "content", "doc_status", 
                         "context_period_start", "context_period_end", "encounter_ref", "encounter", "ref_num", 
                         "text", "authenticator_reference", "authenticator_display", "custodian_reference", 
                         "custodian_display", "author_reference", "author_display", "identifier", 
                         "category", "meta_last_updated", "meta_version_id", "status", "raw_data"]
                    )
                except Exception as e:
                    print("Error during bulk_update:", str(e))

        print("Document reference bulk export completed")
    except Exception as e:
        print(f"Error saving DocumentReferenceBulkExport: {e}")


def save_medication_request_bulk_export(data, medication_ids, user_service):
    """
    Save bulk exported medication_request data to the database.

    This function processes and stores bulk medication_request data for a specific user.

    Args:
        data (dict): The bulk medication_request data to be saved. Typically, this is a dictionary
            containing details about medication_requests, their attributes, and related information.
        medication_ids (list): A list of unique identifiers for the medication_requests to be saved.
        user_service (UserServiceToken): The user service instance associated with the medication_request data.
        
    Returns:
        None
    """

    updated_medications = []
    medication_details = []
    lst_updated_ref_num = []
    lst_created_ref_num = []

    # Fetch existing medication requests based on ref_num and user
    existing_medications = MedicationRequestBulkExport.objects.filter(ref_num__in=medication_ids, user=user_service.user).only('ref_num')
    existing_medications_map = {med.ref_num: med for med in existing_medications}
    
    user_encounters = EncounterBulkExport.objects.filter(user=user_service.user).only('ref_num')
    user_encounters_map = {enc.ref_num: enc for enc in user_encounters}

    try:
        with transaction.atomic():
            for medication_data in data:
                ref_num = medication_data.get('id')
                existing_medication = existing_medications_map.get(ref_num)

                encounter_ref = medication_data.get("encounter", {}).get("reference").split('/')[1] if medication_data.get("encounter", {}).get("reference") else None
                encounter_obj = user_encounters_map.get(encounter_ref)

                if existing_medication:
                    # Update existing medication request with new data from medication_data
                    existing_medication.extension = medication_data.get("extension")
                    existing_medication.substitution = medication_data.get("substitution")
                    existing_medication.course_of_therapy_type = medication_data.get("courseOfTherapyType")
                    existing_medication.subject_reference = medication_data.get("subject", {}).get("reference")
                    existing_medication.subject_display = medication_data.get("subject", {}).get("display")
                    existing_medication.dispense_request = medication_data.get("dispenseRequest")
                    existing_medication.ref_num = medication_data.get("id")
                    existing_medication.text = medication_data.get("text")
                    existing_medication.requester_reference = medication_data.get("requester", {}).get("reference")
                    existing_medication.requester_display = medication_data.get("requester", {}).get("display")
                    existing_medication.identifier = medication_data.get("identifier")
                    existing_medication.reported_boolean = medication_data.get("reportedBoolean", False)
                    existing_medication.authored_on = medication_data.get("authoredOn")
                    existing_medication.encounter_ref =  encounter_ref
                    existing_medication.encounter =  encounter_obj
                    existing_medication.medication_codeable_concept = medication_data.get("medicationCodeableConcept")
                    existing_medication.dosage_instruction = medication_data.get("dosageInstruction")
                    existing_medication.meta_last_updated = medication_data.get("meta", {}).get("lastUpdated")
                    existing_medication.meta_version_id = medication_data.get("meta", {}).get("versionId")
                    existing_medication.category = medication_data.get("category")
                    existing_medication.status = medication_data.get("status")
                    existing_medication.recorder = medication_data.get("recorder")
                    existing_medication.reason_code = medication_data.get("reasonCode")
                    existing_medication.medication_reference = medication_data.get("medicationReference")
                    existing_medication.intent = medication_data.get("intent")
                    existing_medication.raw_data = medication_data

                    # Append to updated medications list
                    updated_medications.append(existing_medication)
                    lst_updated_ref_num.append(existing_medication.ref_num)

                else:
                    # Create a new medication request with provided data
                    new_medication = MedicationRequestBulkExport(
                        extension=medication_data.get("extension"),
                        substitution=medication_data.get("substitution"),
                        course_of_therapy_type=medication_data.get("courseOfTherapyType"),
                        subject_reference=medication_data.get("subject", {}).get("reference"),
                        subject_display=medication_data.get("subject", {}).get("display"),
                        dispense_request=medication_data.get("dispenseRequest"),
                        ref_num=medication_data.get("id"),
                        text=medication_data.get("text"),
                        requester_reference=medication_data.get("requester", {}).get("reference"),
                        requester_display=medication_data.get("requester", {}).get("display"),
                        identifier=medication_data.get("identifier"),
                        reported_boolean=medication_data.get("reportedBoolean", False),
                        authored_on=medication_data.get("authoredOn"),
                        encounter_ref=encounter_ref,
                        encounter =  encounter_obj,
                        medication_codeable_concept=medication_data.get("medicationCodeableConcept"),
                        dosage_instruction=medication_data.get("dosageInstruction"),
                        meta_last_updated=medication_data.get("meta", {}).get("lastUpdated"),
                        meta_version_id=medication_data.get("meta", {}).get("versionId"),
                        category=medication_data.get("category"),
                        status=medication_data.get("status"),
                        recorder=medication_data.get("recorder"),
                        reason_code=medication_data.get("reasonCode"),
                        medication_reference=medication_data.get("medicationReference"),
                        intent=medication_data.get("intent"),
                        user=user_service.user,
                        raw_data=medication_data
                    )

                    # Append to created medications list
                    medication_details.append(new_medication)
                    lst_created_ref_num.append(new_medication.ref_num)

            # Bulk create new medications
            if medication_details:
                try:
                    MedicationRequestBulkExport.objects.bulk_create(medication_details)
                except Exception as e:
                    print("Error during bulk_create:", str(e))
    
            # Bulk update existing medications
            if updated_medications:
                try:
                    MedicationRequestBulkExport.objects.bulk_update(
                        updated_medications,
                        ["extension", "substitution", "course_of_therapy_type", "subject_reference", 
                         "subject_display", "dispense_request", "ref_num", "text", "requester_reference", 
                         "requester_display", "identifier", "reported_boolean", "authored_on", 
                         "encounter_ref", "encounter", "medication_codeable_concept", "dosage_instruction", 
                         "meta_last_updated", "meta_version_id", "category", "status", "recorder", "reason_code",
                         "medication_reference", "intent", "raw_data"]
                    )
                except Exception as e:
                    print("Error during bulk_update:", str(e))

        print("Medication request bulk export completed")
    except Exception as e:
        print(f"Error saving MedicationRequestBulkExport: {e}")