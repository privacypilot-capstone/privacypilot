# Patient data model for HealthTrack India
# Synthetic test app for PrivacyPilot evaluation
# PLANTED VIOLATIONS: V1 (aadhaar), V2 (blood_group), V3 (biometric), V6 (date_of_birth)

from django.db import models

class Patient(models.Model):
    # Basic info
    full_name    = models.CharField(max_length=200)
    email        = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15)

    # PLANTED V1 — Aadhaar collected, never mentioned in privacy policy
    aadhaar_number = models.CharField(max_length=14)

    # PLANTED V2 — Blood group = sensitive health data, not in policy
    blood_group = models.CharField(max_length=5)

    # PLANTED V3 — Biometric data, not in policy
    fingerprint_hash = models.CharField(max_length=256)

    # PLANTED V6 — Date of birth stored but not necessary for service
    date_of_birth = models.DateField()

    # Location
    address  = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.full_name} - {self.aadhaar_number}"
