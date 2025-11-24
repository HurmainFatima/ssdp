from django.urls import path
from .views import (
    FileUploadView, 
    FileListView, 
    FileDownloadView, 
    FileDeleteView,
    ShareFileView,
    SharedWithMeView,
    RevokeShareView,
    FileSharesView
)
urlpatterns = [
    # ✅ File list endpoint (GET /api/files/)
    path('', FileListView.as_view(), name='file-list'),
    
    # File operations
    path('upload/', FileUploadView.as_view(), name='file-upload'),
    path('<uuid:file_id>/download/', FileDownloadView.as_view(), name='file-download'),
    path('<uuid:file_id>/', FileDeleteView.as_view(), name='file-delete'),
    
    # Sharing operations
    path('<uuid:file_id>/share/', ShareFileView.as_view(), name='file-share'),
    path('<uuid:file_id>/shares/', FileSharesView.as_view(), name='file-shares'),
    path('<uuid:file_id>/revoke/', RevokeShareView.as_view(), name='revoke-share'),
    path('shared-with-me/', SharedWithMeView.as_view(), name='shared-with-me'),
]