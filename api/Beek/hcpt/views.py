from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.db.models import F, Value, CharField, FloatField
from django.db.models.functions import Cast, Replace
from decimal import Decimal
from drf_yasg.utils import swagger_auto_schema
from rest_framework.permissions import IsAuthenticated
from beek.permissions import HasActiveSubscription
from hcpt.models import CPTData


class CPTListView(APIView):
    permission_classes = [IsAuthenticated, HasActiveSubscription]

    @swagger_auto_schema(
        operation_summary="Search hospitals by procedure and zip code",
        operation_description="Fetch hospital details and procedure rates based on procedure ID and zip code."
    )
    def post(self, request):
        try:
            procedure_id = request.data.get("procedureId")
            zip_code = request.data.get("zipCode")
            print("CPTListView::::::::::::",procedure_id,zip_code)
            # Check if both procedure_id and zip_code are provided
            if not procedure_id or not zip_code:
                return Response({"message": "Both Procedure ID and Zip Code are required"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Query the CPTData table for matching procedure_id and zip_code
            records = CPTData.objects.filter(procedure_id=procedure_id, zip_code=zip_code)

            # Check if records exist
            if records.exists():
                print("CPTListView:::::::::::: records",list(records.values()))
                # Return the found records (You can format them or return them as needed)
                return Response({"records": list(records.values())}, status=status.HTTP_200_OK)
            else:
                # No records found for the given procedure_id and zip_code
                return Response({"message": "No records found for the provided Procedure ID and Zip Code."}, status=status.HTTP_404_NOT_FOUND)
            
        except Exception as e:
            print(f"Error fetching data: {e}")
            return Response({"message": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
