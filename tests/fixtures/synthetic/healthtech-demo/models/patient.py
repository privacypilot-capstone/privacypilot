
from django.db import models


class Patient(models.Model):
    # Basic patient information
    full_name = models.CharField(max_length=200)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15)

    # Identity information
    aadhaar_number = models.CharField(max_length=14)

    # Health information
    blood_group = models.CharField(max_length=5)
    fingerprint_hash = models.CharField(max_length=256)

    # Patient profile information
    date_of_birth = models.DateField()
    address = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.full_name} - {self.aadhaar_number}"


# Negative-control comment:
# Documentation may discuss Aadhaar, PAN, fingerprint data, Firebase,
# and other identifiers without performing any collection or transmission.
# The scanner should distinguish comments from executable data flows.
