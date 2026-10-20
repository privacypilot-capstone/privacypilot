# API views for LoanEasy India
# PLANTED VIOLATIONS: aggregates all PII handling

from models.customer import Customer
from services.analytics import track_loan_application

def apply_for_loan(request):
    data = request.POST
    customer = Customer.objects.create(
        full_name           = data['full_name'],
        email               = data['email'],
        phone_number        = data['phone_number'],
        pan_number          = data['pan_number'],
        bank_account_number = data['bank_account_number'],
        ifsc_code           = data['ifsc_code'],
        aadhaar_number      = data['aadhaar_number'],
    )
    track_loan_application(customer)
    return {"status": "applied", "id": customer.id}


def get_customer_profile(request, customer_id):
    customer = Customer.objects.get(id=customer_id)
    return {
        "name":           customer.full_name,
        "pan":            customer.pan_number,
        "bank_account":   customer.bank_account_number,
        "aadhaar":        customer.aadhaar_number,
        "credit_score":   customer.credit_score,
    }
