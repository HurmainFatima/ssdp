from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse

def health_check(request):
    return JsonResponse({'status': 'healthy'})

urlpatterns = [
    path('admin/', admin.site.urls),
    path('health/', health_check),
    path('api/auth/', include('accounts.urls')),
    path('api/files/', include('files.urls')),
    path('api/audit/', include('audit.urls')),
]