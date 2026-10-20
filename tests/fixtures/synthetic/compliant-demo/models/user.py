# User model for ShopIndia ecommerce
# Synthetic COMPLIANT app for PrivacyPilot evaluation
# NO VIOLATIONS PLANTED — everything disclosed in privacy policy

from django.db import models

class User(models.Model):
    # All fields below are explicitly disclosed in privacy policy
    full_name    = models.CharField(max_length=200)
    email        = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15)
    address      = models.TextField()
    created_at   = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.full_name} - {self.email}"


class Order(models.Model):
    user       = models.ForeignKey(User, on_delete=models.CASCADE)
    product    = models.CharField(max_length=200)
    amount     = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
