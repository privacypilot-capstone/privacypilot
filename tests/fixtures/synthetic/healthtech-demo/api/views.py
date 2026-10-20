# API views for HealthTrack India
# Additional PII handling

from django.http import JsonResponse
from models.patient import Patient
from services.analytics import track_patient_event
from services.notifications import send_appointment_sms
from services.tracking import track_patient_location

def register_patient(request):
    """Register a new patient"""
    data = request.POST
    patient = Patient.objects.create(
        full_name      = data['full_name'],
        email          = data['email'],
        phone_number   = data['phone_number'],
        aadhaar_number = data['aadhaar_number'],
        blood_group    = data['blood_group'],
        date_of_birth  = data['date_of_birth'],
        address        = data['address'],
    )
    # Send to analytics
    track_patient_event(patient)
    send_appointment_sms(patient)
    return JsonResponse({"status": "registered", "id": patient.id})


def get_patient_report(request, patient_id):
    """Get full patient report including all sensitive data"""
    patient = Patient.objects.get(id=patient_id)
    return JsonResponse({
        "name":           patient.full_name,
        "aadhaar":        patient.aadhaar_number,
        "blood_group":    patient.blood_group,
        "fingerprint":    patient.fingerprint_hash,
        "date_of_birth":  str(patient.date_of_birth),
        "phone":          patient.phone_number,
    })
