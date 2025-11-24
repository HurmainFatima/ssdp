from django.db import models
from accounts.models import User
import uuid
import hashlib

class EncryptedFile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_files')
    original_filename = models.CharField(max_length=255)
    encrypted_filename = models.CharField(max_length=255, unique=True)
    file_size = models.BigIntegerField()
    file_hash = models.CharField(max_length=64)
    encryption_metadata = models.JSONField()
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_deleted = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-uploaded_at']
        
class FileShare(models.Model):
    PERMISSION_CHOICES = [
        ('VIEW', 'View Only'),
        ('DOWNLOAD', 'Can Download'),
        ('RESHARE', 'Can Re-share'),
    ]
    
    file = models.ForeignKey(EncryptedFile, on_delete=models.CASCADE, related_name='shares')
    shared_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='shared_files')
    shared_with = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_shares')
    permission = models.CharField(max_length=20, choices=PERMISSION_CHOICES, default='VIEW')
    can_download = models.BooleanField(default=True)
    can_reshare = models.BooleanField(default=False)
    shared_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_revoked = models.BooleanField(default=False)
    
    class Meta:
        unique_together = ['file', 'shared_with']
        ordering = ['-shared_at']
    
    def __str__(self):
        return f"{self.file.original_filename} shared with {self.shared_with.username}"
    
    def is_expired(self):
        if self.expires_at:
            from django.utils import timezone
            return timezone.now() > self.expires_at
        return False
    
    def has_permission(self, permission_type):
        if self.is_revoked or self.is_expired():
            return False
        
        if permission_type == 'VIEW':
            return True
        elif permission_type == 'DOWNLOAD':
            return self.can_download
        elif permission_type == 'RESHARE':
            return self.can_reshare
        return False