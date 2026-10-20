# Analytics service
# PLANTED VIOLATIONS: V4 (financial data sent to Segment)

import segment.analytics as analytics

SEGMENT_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxx"
analytics.write_key = SEGMENT_KEY

def track_loan_application(customer):
    """
    PLANTED V4 — Sends financial data to Segment analytics.
    Bank account and PAN sent to third-party without disclosure.
    """
    analytics.track(customer.email, 'loan_applied', {
        'pan_number':          customer.pan_number,
        'bank_account_number': customer.bank_account_number,
        'credit_score':        customer.credit_score,
        'aadhaar':             customer.aadhaar_number,
    })


def track_login(customer):
    """Tracks login events"""
    analytics.track(customer.email, 'login', {
        'phone': customer.phone_number,
        'name':  customer.full_name,
    })
