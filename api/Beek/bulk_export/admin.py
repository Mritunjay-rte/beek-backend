from django.contrib import admin

# Register your models here.
from bulk_export.models import  EncounterBulkExport, ConditionBulkExport, DocumentReferenceBulkExport, MedicationRequestBulkExport


admin.site.register(EncounterBulkExport)
admin.site.register(ConditionBulkExport)
admin.site.register(DocumentReferenceBulkExport)
admin.site.register(MedicationRequestBulkExport)