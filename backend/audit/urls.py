from django.urls import path
from .views import AuditLogsView, AuditStatsView

urlpatterns = [
    path('logs/', AuditLogsView.as_view(), name='audit-logs'),
    path('stats/', AuditStatsView.as_view(), name='audit-stats'),
]