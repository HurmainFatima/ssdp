from django.contrib import admin
from .models import AuditLog

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'user', 'action', 'severity', 'ip_address')
    list_filter = ('action', 'severity', 'timestamp')
    search_fields = ('user__username', 'user__email', 'ip_address', 'details')
    readonly_fields = ('user', 'action', 'timestamp', 'ip_address', 'user_agent', 'details', 'severity')
    ordering = ('-timestamp',)
    
    def has_add_permission(self, request):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False