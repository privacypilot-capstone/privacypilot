# Customer data model for LoanEasy India
# Synthetic fintech app for PrivacyPilot evaluation
# PLANTED VIOLATIONS: V1 (pan_number), V2 (bank_account), V3 (aadhaar)

from django.db import models

class Customer(models.Model):
    # Basic info
    full_name    = models.CharField(max_length=200)
    email        = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15)

    # PLANTED V1 — PAN number for KYC, not in privacy policy
    pan_number = models.CharField(max_length=10)

    # PLANTED V2 — Bank account for loan disbursal, not in policy
    bank_account_number = models.CharField(max_length=20)
    ifsc_code           = models.CharField(max_length=11)

    # PLANTED V3 — Aadhaar for identity verification, not in policy
    aadhaar_number = models.CharField(max_length=14)

    # Credit info
    credit_score = models.IntegerField(default=0)
    created_at   = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.full_name} - {self.pan_number}"
