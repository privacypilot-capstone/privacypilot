"""Student data model for LearnIndia."""

from django.db import models


# Benchmark negative control:
# References to Aadhaar, PAN, and Firebase in this comment are
# examples for privacy-review testing only. They are not model
# fields and do not represent collection or transmission.


class Student(models.Model):
    # Basic information
    full_name = models.CharField(max_length=200)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15)

    # Intentionally retained benchmark case: date of birth is
    # collected in code but is not listed in the privacy policy.
    date_of_birth = models.DateField()

    # Intentionally retained benchmark case: location fields are
    # collected in code but are not listed in the privacy policy.
    latitude = models.DecimalField(max_digits=9, decimal_places=6)
    longitude = models.DecimalField(max_digits=9, decimal_places=6)
    address = models.TextField()

    # Academic information
    course_enrolled = models.CharField(max_length=200)
    progress = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.full_name} - {self.course_enrolled}"
