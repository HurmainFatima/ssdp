from django.urls import path
from .views import (
    RegisterView, 
    LoginView, 
    EnableMFAView, 
    VerifyMFAView, 
    DisableMFAView,
    GetUserProfileView,
    AdminUsersView,
    AdminUpdateUserRoleView,
    AdminToggleUserStatusView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('mfa/enable/', EnableMFAView.as_view(), name='enable-mfa'),
    path('mfa/verify/', VerifyMFAView.as_view(), name='verify-mfa'),
    path('mfa/disable/', DisableMFAView.as_view(), name='disable-mfa'),
    path('profile/', GetUserProfileView.as_view(), name='user-profile'),
    
    # Admin endpoints
    path('admin/users/', AdminUsersView.as_view(), name='admin-users'),
    path('admin/users/<int:user_id>/role/', AdminUpdateUserRoleView.as_view(), name='admin-update-role'),
    path('admin/users/<int:user_id>/toggle/', AdminToggleUserStatusView.as_view(), name='admin-toggle-status'),
]