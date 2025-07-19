from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _

"""
Custom user model for Firebase authentication.
Extends Django's AbstractUser with Firebase-specific fields.
"""
class FirebaseUser(AbstractUser):
   
    # Firebase UID - unique identifier from Firebase Auth
    firebase_uid = models.CharField(max_length=128, unique=True, null=True, blank=True, help_text='Firebase UID for this user')
    
    phone_number = models.CharField(max_length=20, null=True, blank=True, help_text='Usersphone number')
    
    # Profile picture URL (stored on Firebase Storage)
    profile_picture_url = models.URLField(max_length=500, null=True, blank=True, help_text='URL to usersprofile picture')
    
    # User role for access control
    USER_ROLES = ('user', _('User')),('admin', _('Admin'))

    role = models.CharField(max_length=10, choices=USER_ROLES, default='user', help_text='User role for access control')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Firebase User'
        verbose_name_plural = 'Firebase Users'

    def __str__(self):
        return f"{self.username} ({self.firebase_uid})"

    # Check if user has admin role. 
    @property
    def is_admin(self):
        return self.role == 'admin'
