
from django.db import models


class UserAccount(models.Model):
    username = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15)
    password = models.CharField(max_length=256)

    # Additional account field used to test data-minimisation analysis.
    pan_number = models.CharField(max_length=10)

    # Profile information
    profile_photo = models.ImageField(upload_to="profiles/")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "user_accounts"
