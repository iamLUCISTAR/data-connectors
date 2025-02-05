from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    google_access_token = models.TextField(blank=True, null=True)
    google_refresh_token = models.TextField(blank=True, null=True)
    google_token_expiry = models.DateTimeField(blank=True, null=True)
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='customuser_groups',  # Add related_name to avoid clash
        blank=True
    )

    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='customuser_permissions',  # Add related_name to avoid clash
        blank=True
    )