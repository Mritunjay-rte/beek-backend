from django_filters import rest_framework as filters
from .models import Document, Encounter
from rest_framework import serializers
from datetime import datetime


class DocumentFilter(filters.FilterSet):
    """
    A custom filter set for filtering `Document` objects based on category.

    Filters:
        - `category`: Filters documents based on their category selected by user (e.g., 'blood_results', 'x_rays', 'imaging', 'lab_tests', 'vaccines', 'fertility', 'genetics', 'others', 'synchronized').

    """
    category = filters.ChoiceFilter(choices=Document.DOCUMENT_CHOICES)

    class Meta:
        model = Document
        fields = ['category']



class EncounterFilter(filters.FilterSet):
    """
    A custom filter set for filtering `Encounter` objects based on encounter/visits date.

    Filters:
        - `from_date`: Filters encounter entries starting from the date provided.
        - `to_date`: Filters encounter entries upto the date provided.

    Methods:
        - `filter_from_date(queryset, name, value)`: Filters encounter entries starting from the date provided. If date format is incorrect, a validation error message returned.
        - `filter_to_date(queryset, name, value)`: Filters encounter entries upto the date provided. If date format is incorrect, a validation error message returned.
    """
    from_date = filters.DateTimeFilter(field_name='encounter_date', method='filter_from_date')
    to_date = filters.DateTimeFilter(field_name='encounter_date', method='filter_to_date')
    
    def filter_from_date(self, queryset, name, value):
        from_date = self.data.get('from_date', [])
        try:
            date_object = datetime.strptime(from_date, '%Y-%m-%d')
            return queryset.filter(encounter_date__gte=date_object.strftime("%Y-%m-%d 00:00:00"))
        except:
            raise serializers.ValidationError({"message": "Invalid date format, "
                                                          "please ensure the from date format is yyyy-mm-dd "})

    def filter_to_date(self, queryset, name, value):
        to_date = self.data.get('to_date', [])
        try:
            date_object = datetime.strptime(to_date, '%Y-%m-%d')
            return queryset.filter(encounter_date__lte=date_object.strftime("%Y-%m-%d 23:59:59"))
        except:
            raise serializers.ValidationError({"message": "Invalid date format, "
                                                          "please ensure the to date format is yyyy-mm-dd "})


    class Meta:
        model = Encounter
        fields = ['from_date', 'to_date']
