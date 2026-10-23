"""Customer data model for LoanEasy India."""

from django.db import models


# Benchmark negative control:
# The terms "Aadhaar", "PAN", and "Firebase" in this comment
# are documentation examples only. They are not additional model
# fields and do not establish that those data types are processed
# by any third-party service.


class Customer(models.Model):
    # Basic information disclosed in the privacy policy
    full_name = models.CharField(max_length=200)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15)

    # Benchmark case: PAN is collected but omitted from the policy.
    pan_number = models.CharField(max_length=10)

    # Benchmark case: bank details are collected but omitted
    # from the policy.
    bank_account_number = models.CharField(max_length=20)
    ifsc_code = models.CharField(max_length=11)

    # Benchmark case: Aadhaar is collected but omitted
    # from the policy.
    aadhaar_number = models.CharField(max_length=14)

    # Credit information
    credit_score = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.full_name} - {self.pan_number}"
