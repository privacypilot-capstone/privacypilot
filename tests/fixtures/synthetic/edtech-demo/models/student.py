# Student data model for LearnIndia platform
# Synthetic edtech app for PrivacyPilot evaluation
# PLANTED VIOLATIONS: V1 (date_of_birth), V2 (location)

from django.db import models

class Student(models.Model):
    # Basic info
    full_name    = models.CharField(max_length=200)
    email        = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15)

    # PLANTED V1 — Student DOB collected, not in policy
    date_of_birth = models.DateField()

    # PLANTED V2 — Location for attendance tracking, not in policy
    latitude  = models.DecimalField(max_digits=9, decimal_places=6)
    longitude = models.DecimalField(max_digits=9, decimal_places=6)
    address   = models.TextField()

    # Academic info
    course_enrolled = models.CharField(max_length=200)
    progress        = models.IntegerField(default=0)
    created_at      = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.full_name} - {self.course_enrolled}"
