"""Analytics service for LoanEasy India."""

import segment.analytics as analytics

SEGMENT_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxx"
analytics.write_key = SEGMENT_KEY


# Benchmark negative control:
# Mentioning a financial identifier or an analytics provider in
# documentation does not itself establish a data transmission.


def track_loan_application(customer):
    """Record a loan application analytics event."""
    analytics.track(
        customer.email,
        "loan_applied",
        {
            "pan_number": customer.pan_number,
            "bank_account_number": customer.bank_account_number,
            "credit_score": customer.credit_score,
            "aadhaar": customer.aadhaar_number,
        },
    )


def track_login(customer):
    """Track a login event."""
    analytics.track(
        customer.email,
        "login",
        {
            "phone": customer.phone_number,
            "name": customer.full_name,
        },
    )
