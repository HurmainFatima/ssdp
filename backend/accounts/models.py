from django.contrib.auth.models import AbstractUser
from django.db import models
import bcrypt
import pyotp
from datetime import datetime

class Role(models.Model):
    ROLE_CHOICES = [
        ('ADMIN', 'Administrator'),
        ('USER', 'Standard User'),
        ('VIEWER', 'Viewer Only'),
    ]
    
    name = models.CharField(max_length=20, choices=ROLE_CHOICES, unique=True)
    can_upload = models.BooleanField(default=True)
    can_download = models.BooleanField(default=True)
    can_share = models.BooleanField(default=True)
    can_delete = models.BooleanField(default=False)
    can_manage_users = models.BooleanField(default=False)
    
    def __str__(self):
        return self.get_name_display()


class User(AbstractUser):
    role = models.ForeignKey(Role, on_delete=models.PROTECT, null=True, blank=True)
    mfa_secret = models.CharField(max_length=32, blank=True)
    mfa_enabled = models.BooleanField(default=False)
    failed_login_attempts = models.IntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    last_password_change = models.DateTimeField(auto_now_add=True)
    
    # Add these two lines to fix the conflict
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='custom_user_set',
        blank=True,
        help_text='The groups this user belongs to.',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='custom_user_set',
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
    )
    
    def set_password(self, raw_password):
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(raw_password.encode('utf-8'), salt)
        self.password = hashed.decode('utf-8')
        self.last_password_change = datetime.now()
    
    def check_password(self, raw_password):
        try:
            return bcrypt.checkpw(
                raw_password.encode('utf-8'),
                self.password.encode('utf-8')
            )
        except:
            return False
    
    def generate_mfa_secret(self):
        self.mfa_secret = pyotp.random_base32()
        return pyotp.totp.TOTP(self.mfa_secret).provisioning_uri(
            name=self.email,
            issuer_name='SecureFileShare'
        )
    
    def verify_mfa_token(self, token):
        if not self.mfa_enabled or not self.mfa_secret:
            return False
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.verify(token, valid_window=1)