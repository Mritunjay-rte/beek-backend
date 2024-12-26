from django.contrib import admin

from health.models import Service, UserServiceToken, Encounter, Condition, Prescription, DataSyncLog, Allergy, Immunization,\
                          Document, CeleryTaskmeta, ExternalAPILog, ServiceProvider, Provider


admin.site.register(Service)
admin.site.register(UserServiceToken)
admin.site.register(Encounter)
admin.site.register(Condition)
admin.site.register(Prescription)
admin.site.register(DataSyncLog)
admin.site.register(Allergy)
admin.site.register(Immunization)
admin.site.register(Document)
admin.site.register(CeleryTaskmeta)
admin.site.register(ExternalAPILog)
admin.site.register(ServiceProvider)
admin.site.register(Provider)
