from rest_framework.views import APIView
from rest_framework.response import Response
from .models import AuditLog
from accounts.models import User
import jwt
from django.conf import settings
from datetime import datetime, timedelta
from django.db.models import Q

class AuditLogsView(APIView):
    def get(self, request):
        try:
            # Get authenticated user
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                AuditLog.log_event(
                    action='UNAUTHORIZED_ACCESS',
                    details={'endpoint': '/api/audit/logs/', 'reason': 'No token'},
                    request=request,
                    severity='MEDIUM'
                )
                return Response({'error': 'Authentication required'}, status=401)
            
            token = auth_header.split(' ')[1]
            
            try:
                payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
                user = User.objects.get(id=payload['user_id'])
            except:
                AuditLog.log_event(
                    action='UNAUTHORIZED_ACCESS',
                    details={'endpoint': '/api/audit/logs/', 'reason': 'Invalid token'},
                    request=request,
                    severity='MEDIUM'
                )
                return Response({'error': 'Invalid token'}, status=401)
            
            # Check if user is admin
            if not user.role or not user.role.can_manage_users:
                AuditLog.log_event(
                    action='UNAUTHORIZED_ACCESS',
                    user=user,
                    details={'endpoint': '/api/audit/logs/', 'reason': 'Not admin'},
                    request=request,
                    severity='HIGH'
                )
                return Response({'error': 'Admin access required'}, status=403)
            
            # Get query parameters
            action = request.GET.get('action')
            severity = request.GET.get('severity')
            user_id = request.GET.get('user_id')
            start_date = request.GET.get('start_date')
            end_date = request.GET.get('end_date')
            search = request.GET.get('search')
            limit = int(request.GET.get('limit', 100))
            
            # Build query
            logs = AuditLog.objects.all()
            
            if action:
                logs = logs.filter(action=action)
            
            if severity:
                logs = logs.filter(severity=severity)
            
            if user_id:
                logs = logs.filter(user_id=user_id)
            
            if start_date:
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                logs = logs.filter(timestamp__gte=start_dt)
            
            if end_date:
                end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                logs = logs.filter(timestamp__lte=end_dt)
            
            if search:
                logs = logs.filter(
                    Q(user__username__icontains=search) |
                    Q(user__email__icontains=search) |
                    Q(ip_address__icontains=search) |
                    Q(details__icontains=search)
                )
            
            # Limit results
            logs = logs[:limit]
            
            # Convert to list
            log_list = [log.to_dict() for log in logs]
            
            return Response({
                'logs': log_list,
                'total': len(log_list),
                'filters': {
                    'action': action,
                    'severity': severity,
                    'user_id': user_id,
                    'start_date': start_date,
                    'end_date': end_date,
                    'search': search,
                }
            }, status=200)
        
        except Exception as e:
            return Response({'error': str(e)}, status=500)


class AuditStatsView(APIView):
    def get(self, request):
        try:
            # Get authenticated user
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return Response({'error': 'Authentication required'}, status=401)
            
            token = auth_header.split(' ')[1]
            
            try:
                payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
                user = User.objects.get(id=payload['user_id'])
            except:
                return Response({'error': 'Invalid token'}, status=401)
            
            # Check if user is admin
            if not user.role or not user.role.can_manage_users:
                return Response({'error': 'Admin access required'}, status=403)
            
            # Get date range (last 7 days)
            end_date = datetime.now()
            start_date = end_date - timedelta(days=7)
            
            # Get statistics
            total_logs = AuditLog.objects.filter(timestamp__gte=start_date).count()
            
            # Count by action
            login_success = AuditLog.objects.filter(action='LOGIN_SUCCESS', timestamp__gte=start_date).count()
            login_failed = AuditLog.objects.filter(action='LOGIN_FAILED', timestamp__gte=start_date).count()
            file_uploads = AuditLog.objects.filter(action='FILE_UPLOADED', timestamp__gte=start_date).count()
            file_downloads = AuditLog.objects.filter(action='FILE_DOWNLOADED', timestamp__gte=start_date).count()
            
            # Count by severity
            critical_alerts = AuditLog.objects.filter(severity='CRITICAL', timestamp__gte=start_date).count()
            high_alerts = AuditLog.objects.filter(severity='HIGH', timestamp__gte=start_date).count()
            
            # Recent security alerts
            security_alerts = AuditLog.objects.filter(
                Q(action='SECURITY_ALERT') | Q(action='UNAUTHORIZED_ACCESS'),
                timestamp__gte=start_date
            ).order_by('-timestamp')[:10]
            
            return Response({
                'total_logs': total_logs,
                'login_success': login_success,
                'login_failed': login_failed,
                'file_uploads': file_uploads,
                'file_downloads': file_downloads,
                'critical_alerts': critical_alerts,
                'high_alerts': high_alerts,
                'recent_alerts': [alert.to_dict() for alert in security_alerts],
                'date_range': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat()
                }
            }, status=200)
        
        except Exception as e:
            return Response({'error': str(e)}, status=500)
