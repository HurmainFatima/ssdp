from django.db import models
from accounts.models import User
class AuditLog(models.Model):
    ACTION_CHOICES = [
        ('USER_REGISTERED', 'User Registered'),
        ('LOGIN_SUCCESS', 'Login Success'),
        ('LOGIN_FAILED', 'Login Failed'),
        ('LOGOUT', 'User Logout'),
        ('FILE_UPLOADED', 'File Uploaded'),
        ('FILE_DOWNLOADED', 'File Downloaded'),
        ('FILE_SHARED', 'File Shared'),
        ('FILE_DELETED', 'File Deleted'),
        ('SHARE_REVOKED', 'Share Revoked'),
        ('ROLE_CHANGED', 'User Role Changed'),
        ('MFA_ENABLED', 'MFA Enabled'),
        ('MFA_DISABLED', 'MFA Disabled'),
        ('PASSWORD_CHANGED', 'Password Changed'),
        ('ACCOUNT_LOCKED', 'Account Locked'),
        ('SECURITY_ALERT', 'Security Alert'),
        ('UNAUTHORIZED_ACCESS', 'Unauthorized Access Attempt'),
    ]
    
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    details = models.JSONField(default=dict)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='LOW')
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['action', '-timestamp']),
            models.Index(fields=['severity', '-timestamp']),
        ]
    
    def __str__(self):
        user_str = self.user.username if self.user else 'Anonymous'
        return f"{user_str} - {self.action} - {self.timestamp}"
    
    @classmethod
    def log_event(cls, action, user=None, details=None, request=None, severity='LOW'):
        """Create audit log entry"""
        log_entry = cls(
            user=user,
            action=action,
            details=details or {},
            severity=severity
        )
        
        if request:
            # Get IP address
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                log_entry.ip_address = x_forwarded_for.split(',')[0]
            else:
                log_entry.ip_address = request.META.get('REMOTE_ADDR')
            
            log_entry.user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        log_entry.save()
        return log_entry
    
    def to_dict(self):
        """Convert to dictionary for API response"""
        return {
            'id': self.id,
            'user': self.user.username if self.user else 'Anonymous',
            'user_email': self.user.email if self.user else None,
            'action': self.action,
            'action_display': self.get_action_display(),
            'timestamp': self.timestamp.isoformat(),
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'details': self.details,
            'severity': self.severity,
            'severity_display': self.get_severity_display(),
        }
