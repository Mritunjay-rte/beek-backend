from rest_framework import serializers
from rest_framework.serializers import ModelSerializer
from health.models import Provider, Prescription, Allergy, Immunization, Document, ServiceProvider, Encounter, Condition, EvexiaMenu, EvexiaPatient, EvexiaOrders
from user.models import PersonalInfo
from user.models import ALLOWED_EXCERCISE_CHOICES, ALLOWED_GOALS_CHOICES
from rest_framework.exceptions import ValidationError
import re
from datetime import datetime, timedelta


class ProvidersListSerializer(ModelSerializer):
    """
    Serializer for serializing provider list data.

    Fields:
        - `id`: The unique identifier of the provider.
        - `name`: The provider name.
        - `reference`: The provider reference id in 1UP.
        - `is_active`: Is the provider available or not for the user to connect.
    """
    name = serializers.CharField()
    class Meta:
        model = Provider
        fields = ['id', 'name', 'reference', 'is_active']


class PrescriptionSerializer(ModelSerializer):
    """
    Serializer for the Prescription model.

    Fields:
        - `id`: The unique identifier of the provider.
        - `medication`: The name of the prescribed medication.
        - `active_substance`: The active ingredient(s) in the medication.
        - `prescribed_by`: The name of the healthcare provider who prescribed the medication.

        - `prescription_expiry`: The expiration date of the prescription.
        - `directions`: The directions for taking the prescribed medication.
        - `pharmacy`: The name of the pharmacy where the medication is prescribed to be filled.
        - `pharmacy_location`: The location of the pharmacy.

        - `allergy_intolerance`: Information about allergies or intolerances related to the prescription.
        - `is_self_created`: A flag indicating whether the prescription was self-created (default is False).
        - `user`: The user’s ID.
    """
    
    class Meta:
        model = Prescription
        fields = ['id', 'medication', 'active_substance', 'prescribed_by', 'prescription_expiry', 'directions', 'pharmacy', 'pharmacy_location',
                  'allergy_intolerance', 'is_self_created', 'user']


class GeneralHealthSerializer(ModelSerializer):
    """
    Serializer used by questionnaire for serializing personal info.
    Validates mandatory fields, field types and file formats.

    Fields:
        - `id`: The unique identifier of the personal info entry of the user.
        - `birth_date`: The birth date of user.
        - `zip_code`: Address zipcode of user.
        - `feet`: User height in feet.
 
        - `inches`: User height in inches.
        - `weight`: The weight of user.
        - `insurance_company_name`: Name of insurance company user have registered.
        - `insurance_no`: If user has insurance, the insurance number.

        - `sponsor_name`: If user has insurance, name of the sponsored person.
        - `photo`: S3 url of insurance document.
        - `file_name`: insurance document file name.
        - `is_smoker`: Boolean field, true if user smokes else, false.

        - `gender`: The gender of account holder.
        - `exercise_frequency`: If the user exercise regulary, then the frequency of excercise.
        - `excercise_activities`: If the user exercise regulary, then the types of excercises.
        - `excercise_time`: If the user exercise regulary, time taken for each workout session.
        
        - `goal`: Goal set by the user for using the application.
        - `user`: The user’s ID.

    Methods:
        - validate_photo: Validates uploaded file type.
        - validate: Validates mandatory fields and value types.
    """
    photo = serializers.FileField(required=False)
    file_name = serializers.CharField(required=False)

    def validate_photo(self, value):
        """
        Ensure only JPG, PNG, or PDF files are allowed.

        Args:
            value (request): The file object.

        Returns:
            value: The file object if success else validation error message.
        """
        ext = value.name.split('.')[-1].lower()
        if ext not in ['jpg', 'jpeg', 'png', 'pdf']:
            raise serializers.ValidationError("File type not supported. Only JPG, PNG, and PDF are allowed.")
        return value
    
    def validate(self, attrs):
        """
        Validates mandatory fields and value types.

        Args:
            attrs (request): Field values to be updated.

        Returns:
            attrs: Validated data if success else validation error message.
        """
        zip_code = attrs.get("zip_code")
        feet = attrs.get("feet")
        inches = attrs.get("inches")
        weight = attrs.get("weight")
        birth_date = attrs.get("birth_date")
        if zip_code and (not re.match(r'^[0-9-]{5,10}$', zip_code)):
            raise serializers.ValidationError("Invalid zip code")
        if feet and (not re.match(r'^(?:[2-9]|10)$', feet)):
            raise serializers.ValidationError("Invalid height")
        if inches and (not re.match(r'^(?:[0-9]|1[01])$', inches)):
            raise serializers.ValidationError("Invalid height")
        if weight and (not re.match(r'^(?!0\.0$)(0?\.\d{1,2}|[1-9]\d{0,3}(\.\d{1,2})?)$', weight)):
            raise serializers.ValidationError("Invalid weight")
        
        max_age_years = 120
        min_birth_date = datetime.today().date() - timedelta(days=max_age_years * 365)

        if birth_date and (birth_date >= datetime.today().date() or birth_date < min_birth_date):
            raise serializers.ValidationError("Invalid birth date")
        
        return attrs
    
    class Meta:
        model = PersonalInfo
        fields = ['id', 'birth_date', 'zip_code', 'feet', 'inches', 'weight', 
                  'insurance_company_name', 'insurance_no', 'sponsor_name', 
                  'photo', 'file_name', 'is_smoker', 'gender', 'exercise_frequency', 'excercise_activities',
                  'excercise_time', 'goal',
                  'user']
    def to_representation(self, instance):
        data = super(GeneralHealthSerializer, self).to_representation(instance)
        data['gender'] = instance.gender
        data['exercise_frequency'] = instance.exercise_frequency
        data['excercise_activities'] = instance.excercise_activities
        data['excercise_time'] = instance.excercise_time
        data['goal'] = instance.goal
        return data


class AllergySerializer(ModelSerializer):
    """
    Serializer for the allergy model serializing for listing and validations.
    Validates file formats.

    Fields:
        - `id`: The unique identifier of the allergy entry of the user.
        - `type`: The type of allergy the user diagnozed with.
        - `file`: Any documents associated with allergy report.
        - `user`: The user's ID.
        - `file_name`: Uploaded file name.

    Methods:
        validate_file: Validates uploaded file type.
    """
    file = serializers.FileField(required=False)

    def validate_file(self, value):
        """
        Ensure only JPG, PNG, or PDF files are allowed.

        Args:
            value (request): The file object.

        Returns:
            value: The file object if success else validation error message.
        """
        ext = value.name.split('.')[-1].lower()
        if ext not in ['jpg', 'jpeg','png', 'pdf']:
            raise serializers.ValidationError("File type not supported. Only JPG, PNG, and PDF are allowed.")
        return value
    
    class Meta:
        model = Allergy
        fields = ['id', 'type', 'file', 'user', 'file_name']
        

class ImmunizationSerializer(ModelSerializer):
    """
    Serializer for the Immunization model serializing for listing, validations, and saving data.

    Fields:
        - `id`: The unique identifier of the immunization entry of the user.
        - `type`: The type of immunization the user diagnozed with.
        - `file`: Any documents associated with immunization report.
        - `user`: The user's ID.
        - `file_name`: Uploaded file name.

    Methods:
        validate_file: Validates uploaded file type.
    """
    file = serializers.FileField(required=False)

    def validate_file(self, value):
        """
        Ensure only JPG, PNG, or PDF files are allowed.
        """
        ext = value.name.split('.')[-1].lower()
        if ext not in ['jpg', 'jpeg', 'png', 'pdf']:
            raise serializers.ValidationError("File type not supported. Only JPG, PNG, and PDF are allowed.")
        return value
    
    
    class Meta:
        model = Immunization
        fields = ['id', 'type', 'file', 'user', 'file_name']
        


class ProfileAdditionalInfoSerializer(ModelSerializer):
    """
    Serializer for serializing additional info in user profile.

    Fields:
        - `id`: The unique identifier of the personal info of the user.
        - `current_health`: A choice field for current health selected by user.
        - `intensity_of_excercise`: The intensity of the user's exercise routine.
        - `symptom`: The symptoms experienced by the user, selected from predefined choices.
        - `user`: The user's ID.
    """
    class Meta:
        model = PersonalInfo
        fields = ['id', 'current_health', 'intensity_of_excercise', 'symptom', 'user']
    def to_representation(self, instance):
        data = super(ProfileAdditionalInfoSerializer, self).to_representation(instance)
        if instance.goal:
            data['current_health'] = instance.current_health
            data['intensity_of_excercise'] = instance.intensity_of_excercise
            data['symptom'] = instance.symptom
            
        return data
    

class DocumentSerializer(ModelSerializer):
    """
    Serializer for the Documents model. Serializes data for listing, storing and validations.

    Fields:
        - `id`: The unique identifier of the document entry of the user.
        - `category`: The category of the document, chosen from predefined options such as 'Blood Results', 'X-Rays', etc.
        - `title`: The title or name of the document.
        - `notes`: Additional notes or comments about the document.

        - `is_self_created`: A flag indicating whether the document was self-created (default is False).
        - `files`: The file associated with the document.
        - `user`: The user's ID.
        - `file_name`: The name of the file associated with the document.

    Methods:
        validate_files: Validates uploaded files type.
    """
    files = serializers.FileField(required=False)
    file_name = serializers.CharField(required=False)

    def validate_files(self, value):
        """
        Ensure only JPG, PNG, or PDF files are allowed.
        """
        ext = value.name.split('.')[-1].lower()
        if ext not in ['jpg','jpeg', 'png', 'pdf']:
            raise ValidationError("Invalid file format.")
        return value
    
    
    class Meta:
        model = Document
        fields = ['id', 'category', 'title', 'notes', 'is_self_created', 'files', 'user', 'file_name']


class ConnectedProvidersSerializer(ModelSerializer):
    """
    Serializer for serializing providers model. Lists providers connected by a user.

    Fields:
        - `id`: The unique identifier of the service provider connected by the user.
        - `name`: The name of the provider.
        - `reference`: A reference or identifier associated with the provider.
        - `is_active`: A flag indicating whether the provider is active.
    """
    class Meta:
        model = ServiceProvider
        fields = ['id']

    def to_representation(self, instance):
        data = super(ConnectedProvidersSerializer, self).to_representation(instance)
        data['name'] = instance.provider.name
        data['reference'] = instance.provider.reference
        data['is_active'] = instance.provider.is_active
        return data


class EncounterSerializer(ModelSerializer):
    """
    Serializer for listing the Encounters model data added by user.

    Fields:
        `id` : The unique identifier for the encounter.
        `ref_num` : The identifier of the encounter in the 1Up system.
        `facility` : The name of the healthcare facility where the encounter took place.
        `physician` : The name of the physician associated with the encounter.
        `date_of_record` : The date and time when the encounter record was created.
        `encounter_date` : The date and time when the encounter actually occurred.
        `careplan` : The care plan associated with the encounter.
        `condition` : The medical condition diagnosed during the encounter.
        `code` : The code associated with the condition or procedure.
        `record_number` : The unique record number for the encounter.
        `diagnostic_report` : A report detailing the diagnosis for the encounter.
        `medication_order` : The medication prescribed during the encounter.
        `record_synced_at` : The date and time when the encounter record was synced from the 1Up API.
        `user` : The user associated with the encounter.
        `created_at` : The date and time when the encounter record was created.
        `updated_at` : The date and time when the encounter record was last updated.
        `deleted_at` : The date and time when the encounter record was deleted.
    
    """
    class Meta:
        model = Encounter
        fields = '__all__'
        

class ConditionSerializer(ModelSerializer):
    """
    Serializer for listing the Conditions model data added by user.

    Fields:
        `id` : The unique identifier for the condition.
        `ref_num` : The identifier of the encounter in the 1Up system.
        `health_indicator` : A description or label of the health indicator associated with the condition.
        'includes' : The details of what is included under the condition (e.g., related symptoms or conditions).
        'diagnosis_code' : The code associated with the condition, often from a standardized medical coding system.
        'encounter' : The healthcare encounter during which the condition was diagnosed or observed.
        'user' : The user associated with the condition record.
        'created_at': The date and time when the condition record was created.
        'updated_at': The date and time when the condition record was last updated.
        'deleted_at' : The date and time when the condition record was deleted, if applicable.
        'record_synced_at' : The date and time when the condition record was synced from the 1Up API.
    """
    class Meta:
        model = Condition
        fields = '__all__'

class EvexiaMenuSerializer(serializers.ModelSerializer):
    class Meta:
        model = EvexiaMenu
        fields = '__all__'  # Serializes all fields of the EvexiaMenu model

class EvexiaPatientSerializer(serializers.ModelSerializer):
    class Meta:
        model = EvexiaPatient
        fields = '__all__'	

class EvexiaOrdersSerializer(serializers.ModelSerializer):
    documents = serializers.CharField()  # This will preserve the format of the document URL

    class Meta:
        model = EvexiaOrders
        fields = '__all__'