from rest_framework.views import APIView
from rest_framework.response import Response
from .models import User, Role
import jwt
from django.conf import settings
from datetime import datetime, timedelta
import pyotp
import qrcode
import io
import base64

class RegisterView(APIView):
    def post(self, request):
        try:
            email = request.data.get('email')
            password = request.data.get('password')
            username = request.data.get('username')
            
            if not all([email, password, username]):
                return Response({'error': 'Missing required fields'}, status=400)
            
            if len(password) < 12:
                return Response({'error': 'Password must be at least 12 characters'}, status=400)
            
            if User.objects.filter(email=email).exists():
                return Response({'error': 'Email already registered'}, status=400)
            
            default_role, _ = Role.objects.get_or_create(
                name='USER',
                defaults={'can_upload': True, 'can_download': True, 'can_share': True}
            )
            
            user = User.objects.create(
                username=username,
                email=email,
                role=default_role
            )
            user.set_password(password)
            user.save()
            
            return Response({'message': 'User registered successfully'}, status=201)
        
        except Exception as e:
            return Response({'error': 'Registration failed'}, status=500)


class LoginView(APIView):
    def post(self, request):
        try:
            email = request.data.get('email')
            password = request.data.get('password')
            mfa_token = request.data.get('mfa_token')
            
            if not all([email, password]):
                return Response({'error': 'Missing credentials'}, status=400)
            
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({'error': 'Invalid credentials'}, status=401)
            
            if not user.check_password(password):
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.account_locked_until = datetime.now() + timedelta(minutes=15)
                user.save()
                return Response({'error': 'Invalid credentials'}, status=401)
            
            # Check if MFA is enabled
            if user.mfa_enabled:
                if not mfa_token:
                    return Response({
                        'error': 'MFA token required',
                        'mfa_required': True
                    }, status=401)
                
                if not user.verify_mfa_token(mfa_token):
                    return Response({'error': 'Invalid MFA token'}, status=401)
            
            # Reset failed attempts
            user.failed_login_attempts = 0
            user.account_locked_until = None
            user.save()
            
            # Generate JWT token
            payload = {
                'user_id': user.id,
                'email': user.email,
                'role': user.role.name if user.role else 'USER',
                'exp': datetime.utcnow() + settings.JWT_ACCESS_TOKEN_LIFETIME,
                'iat': datetime.utcnow(),
            }
            
            token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
            
            return Response({
                'tokens': {
                    'access_token': token,
                    'refresh_token': token,
                    'expires_in': 3600
                },
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username,
                    'role': user.role.name if user.role else 'USER',
                    'mfa_enabled': user.mfa_enabled
                }
            }, status=200)
        
        except Exception as e:
            return Response({'error': 'Login failed'}, status=500)


class EnableMFAView(APIView):
    def post(self, request):
        try:
            # Get user from token
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return Response({'error': 'Authentication required'}, status=401)
            
            token = auth_header.split(' ')[1]
            
            try:
                payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
                user = User.objects.get(id=payload['user_id'])
            except:
                return Response({'error': 'Invalid token'}, status=401)
            
            # Generate MFA secret
            qr_uri = user.generate_mfa_secret()
            user.save()
            
            # Generate QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(qr_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()
            
            return Response({
                'secret': user.mfa_secret,
                'qr_code': f'data:image/png;base64,{img_str}',
                'message': 'Scan QR code with your authenticator app'
            }, status=200)
        
        except Exception as e:
            return Response({'error': str(e)}, status=500)


class VerifyMFAView(APIView):
    def post(self, request):
        try:
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return Response({'error': 'Authentication required'}, status=401)
            
            token = auth_header.split(' ')[1]
            mfa_token = request.data.get('mfa_token')
            
            if not mfa_token:
                return Response({'error': 'MFA token required'}, status=400)
            
            try:
                payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
                user = User.objects.get(id=payload['user_id'])
            except:
                return Response({'error': 'Invalid token'}, status=401)
            
            if user.verify_mfa_token(mfa_token):
                user.mfa_enabled = True
                user.save()
                return Response({
                    'message': 'MFA enabled successfully',
                    'mfa_enabled': True
                }, status=200)
            else:
                return Response({'error': 'Invalid MFA token'}, status=400)
        
        except Exception as e:
            return Response({'error': str(e)}, status=500)


class DisableMFAView(APIView):
    def post(self, request):
        try:
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return Response({'error': 'Authentication required'}, status=401)
            
            token = auth_header.split(' ')[1]
            password = request.data.get('password')
            
            if not password:
                return Response({'error': 'Password required'}, status=400)
            
            try:
                payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
                user = User.objects.get(id=payload['user_id'])
            except:
                return Response({'error': 'Invalid token'}, status=401)
            
            if not user.check_password(password):
                return Response({'error': 'Invalid password'}, status=401)
            
            user.mfa_enabled = False
            user.mfa_secret = ''
            user.save()
            
            return Response({
                'message': 'MFA disabled successfully',
                'mfa_enabled': False
            }, status=200)
        
        except Exception as e:
            return Response({'error': str(e)}, status=500)


class GetUserProfileView(APIView):
    def get(self, request):
        try:
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return Response({'error': 'Authentication required'}, status=401)
            
            token = auth_header.split(' ')[1]
            
            try:
                payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
                user = User.objects.get(id=payload['user_id'])
            except:
                return Response({'error': 'Invalid token'}, status=401)
            
            return Response({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role.name if user.role else 'USER',
                'mfa_enabled': user.mfa_enabled,
                'date_joined': user.date_joined.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None
            }, status=200)
        
        except Exception as e:
            return Response({'error': str(e)}, status=500)
        
class AdminUsersView(APIView):
    def get(self, request):
        try:
            # Get authenticated user
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return Response({'error': 'Authentication required'}, status=401)
            
            token = auth_header.split(' ')[1]
            
            try:
                payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
                admin_user = User.objects.get(id=payload['user_id'])
            except:
                return Response({'error': 'Invalid token'}, status=401)
            
            # Check if user is admin
            if not admin_user.role or not admin_user.role.can_manage_users:
                from audit.models import AuditLog
                AuditLog.log_event(
                    action='UNAUTHORIZED_ACCESS',
                    user=admin_user,
                    details={'endpoint': '/api/admin/users/', 'reason': 'Not admin'},
                    request=request,
                    severity='HIGH'
                )
                return Response({'error': 'Admin access required'}, status=403)
            
            # Get all users
            users = User.objects.all().select_related('role')
            
            user_list = []
            for user in users:
                user_list.append({
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role.name if user.role else 'USER',
                    'is_active': user.is_active,
                    'mfa_enabled': user.mfa_enabled,
                    'date_joined': user.date_joined.isoformat(),
                    'last_login': user.last_login.isoformat() if user.last_login else None,
                    'failed_login_attempts': user.failed_login_attempts,
                })
            
            return Response({'users': user_list}, status=200)
        
        except Exception as e:
            return Response({'error': str(e)}, status=500)


class AdminUpdateUserRoleView(APIView):
    def post(self, request, user_id):
        try:
            # Get authenticated user
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return Response({'error': 'Authentication required'}, status=401)
            
            token = auth_header.split(' ')[1]
            
            try:
                payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
                admin_user = User.objects.get(id=payload['user_id'])
            except:
                return Response({'error': 'Invalid token'}, status=401)
            
            # Check if user is admin
            if not admin_user.role or not admin_user.role.can_manage_users:
                from audit.models import AuditLog
                AuditLog.log_event(
                    action='UNAUTHORIZED_ACCESS',
                    user=admin_user,
                    details={'endpoint': f'/api/admin/users/{user_id}/role/', 'reason': 'Not admin'},
                    request=request,
                    severity='HIGH'
                )
                return Response({'error': 'Admin access required'}, status=403)
            
            # Get target user
            try:
                target_user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=404)
            
            # Get new role
            new_role_name = request.data.get('role')
            if not new_role_name:
                return Response({'error': 'Role required'}, status=400)
            
            try:
                new_role = Role.objects.get(name=new_role_name)
            except Role.DoesNotExist:
                return Response({'error': 'Invalid role'}, status=400)
            
            # Update role
            old_role = target_user.role.name if target_user.role else 'None'
            target_user.role = new_role
            target_user.save()
            
            # Log the change
            from audit.models import AuditLog
            AuditLog.log_event(
                action='ROLE_CHANGED',
                user=admin_user,
                details={
                    'target_user': target_user.username,
                    'target_email': target_user.email,
                    'old_role': old_role,
                    'new_role': new_role_name
                },
                request=request,
                severity='MEDIUM'
            )
            
            return Response({
                'message': 'User role updated successfully',
                'user': target_user.username,
                'new_role': new_role_name
            }, status=200)
        
        except Exception as e:
            return Response({'error': str(e)}, status=500)


class AdminToggleUserStatusView(APIView):
    def post(self, request, user_id):
        try:
            # Get authenticated user
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return Response({'error': 'Authentication required'}, status=401)
            
            token = auth_header.split(' ')[1]
            
            try:
                payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
                admin_user = User.objects.get(id=payload['user_id'])
            except:
                return Response({'error': 'Invalid token'}, status=401)
            
            # Check if user is admin
            if not admin_user.role or not admin_user.role.can_manage_users:
                return Response({'error': 'Admin access required'}, status=403)
            
            # Get target user
            try:
                target_user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=404)
            
            # Don't allow disabling self
            if target_user.id == admin_user.id:
                return Response({'error': 'Cannot disable your own account'}, status=400)
            
            # Toggle status
            target_user.is_active = not target_user.is_active
            target_user.save()
            
            # Log the change
            from audit.models import AuditLog
            AuditLog.log_event(
                action='ACCOUNT_LOCKED' if not target_user.is_active else 'ROLE_CHANGED',
                user=admin_user,
                details={
                    'target_user': target_user.username,
                    'target_email': target_user.email,
                    'action': 'disabled' if not target_user.is_active else 'enabled'
                },
                request=request,
                severity='HIGH' if not target_user.is_active else 'MEDIUM'
            )
            
            return Response({
                'message': f'User {"disabled" if not target_user.is_active else "enabled"} successfully',
                'user': target_user.username,
                'is_active': target_user.is_active
            }, status=200)
        
        except Exception as e:
            return Response({'error': str(e)}, status=500)
