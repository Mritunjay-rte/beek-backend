from django.urls import path
from .views import (ProvidersList, SendMessage, PrescriptionViewSet, 
                    GeneralHealthView,GeneralHealthMasterData,  AllergyViewSet, ImmunizationViewSet,
                    ProfileAdditionalInfoView, DocumentViewSet, QuestionnaireCount, ConnectedProviders,
                    VisitsListAPIView, ConditionsListAPIView, ViewDocumentAPI, DataSyncRefresh, DashboardRefreshDetails,OrderLabTestListView,PatientAdd, PatientList,OrderAdd,OrderList,OrderPayment,OrderItemsAdd,OrderListPatient,FetchOrderDetails,FetchOrderResults,DeleteItemOrder)
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'prescriptions', PrescriptionViewSet)
router.register(r'allergy', AllergyViewSet)
router.register(r'immunization', ImmunizationViewSet)
router.register(r'documents', DocumentViewSet)

urlpatterns = [
    path('provider-list/', ProvidersList.as_view(), name='provider-list'),
    path('provider/connected/', ConnectedProviders.as_view(), name='provider-connected'),
    path('ws/send/', SendMessage.as_view(), name='ws-send'),
    path('dashboard/refresh/', DataSyncRefresh.as_view(), name='dashboard-refresh'),
    path('masterdata/', GeneralHealthMasterData.as_view(), name='masterdata'),
    path('generalheath/', GeneralHealthView.as_view(), name='generalheath'),
    path('profile/additional-info/', ProfileAdditionalInfoView.as_view(), name='profile-additional-info'),
    path('questionnaire/count/', QuestionnaireCount.as_view(), name='questionnaire-count'),
    path('dashboard/visits/', VisitsListAPIView.as_view(), name='visits'),
    path('dashboard/conditions/', ConditionsListAPIView.as_view(), name='conditions'),
    path('documents/<uuid:doc_id>/view/', ViewDocumentAPI.as_view(), name='document-view'),
    path('dashboard/last-refresh/', DashboardRefreshDetails.as_view(), name='dashboard-last-refresh'),
    path('order-lab-test/', OrderLabTestListView.as_view(), name='order_lab_test'),
    path('patientAdd/', PatientAdd.as_view(), name='patient_add'),
    path('patientList/', PatientList.as_view(), name='patient_list'),
    path('orderAdd/', OrderAdd.as_view(), name='order_add'),
    path('orderList/', OrderList.as_view(), name='order_list'),
    path('orderListPatient/', OrderListPatient.as_view(), name='order_list_patient'),
    path('orderDetails/', FetchOrderDetails.as_view(), name='order_list_patient'),
    path('patient-test-results/', FetchOrderResults.as_view(), name='patient_test-results_results'),
    path('payment/', OrderPayment.as_view(), name='order_payment'),
    path('orderItemsAdd/', OrderItemsAdd.as_view(), name='order_items_add'),
     path('deleteItemOrder/', DeleteItemOrder.as_view(), name='delete_item_order'),

]
urlpatterns += router.urls