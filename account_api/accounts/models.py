from django.db import models
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser


class CustomUser(AbstractBaseUser): 
    STATUS_CHOICES = (
    ("inactive", 'Inactive'),
    ('active', 'Active'),
    
    )
    username = models.TextField(max_length=100)   
    email = models.EmailField(unique=True, max_length=200)
    password = models.CharField(max_length=200)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    phone=models.CharField(max_length=70, default="+234 **********")
    city=models.CharField(max_length=70, default="*****")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='inactive')
    
    
    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['first_name', 'last_name']




class Activation(models.Model): 
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    token = models.CharField(max_length=70, unique=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_valid = models.BooleanField(default=True)
    expires_at = models.DateTimeField(default=timezone.now() + timedelta(days=20))

    def __str__(self):
        return f"Activation for {self.user.username}"
    