from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import JSONParser
from .models import EncryptedFile
from accounts.models import User
import uuid
import os
import base64
from django.conf import settings
import jwt
from accounts.models import User
from .models import FileShare
from audit.models import AuditLog


def get_authenticated_user(request):
    """Extract and validate JWT token"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(
            token, 
            settings.JWT_SECRET_KEY, 
            algorithms=[settings.JWT_ALGORITHM]
        )
        user = User.objects.get(id=payload['user_id'], is_active=True)
        return user
    except Exception as e:
        print(f"Authentication error: {e}")
        return None


# ✅ NEW: File List View (MISSING IN YOUR CODE)
class FileListView(APIView):
    """
    GET /api/files/ - List all files owned by the authenticated user
    """
    def get(self, request):
        try:
            # Get authenticated user
            user = get_authenticated_user(request)
            if not user:
                return Response({
                    'error': 'Authentication required'
                }, status=401)

            # Get files owned by user
            files = EncryptedFile.objects.filter(
                owner=user,
                is_deleted=False
            ).order_by('-uploaded_at')

            file_list = []
            for file in files:
                file_list.append({
                    'id': str(file.id),
                    'original_filename': file.original_filename,
                    'file_size': file.file_size,
                    'file_hash': file.file_hash,
                    'uploaded_at': file.uploaded_at.isoformat(),
                    'owner': user.username,
                    'encryption_metadata': file.encryption_metadata
                })

            return Response({
                'files': file_list,
                'total': len(file_list)
            }, status=200)

        except Exception as e:
            import traceback
            print(f"File list error: {traceback.format_exc()}")
            return Response({
                'error': f'Failed to load files: {str(e)}'
            }, status=500)


class FileUploadView(APIView):
    parser_classes = [JSONParser]

    def post(self, request):
        try:
            # Get authenticated user
            user = get_authenticated_user(request)
            if not user:
                return Response({
                    'error': 'Authentication required'
                }, status=401)

            # Check upload permission
            if user.role and not user.role.can_upload:
                return Response({
                    'error': 'You do not have permission to upload files'
                }, status=403)

            data = request.data
            encrypted_data = data.get('encrypted_data')
            encryption_metadata = data.get('encryption_metadata', {})
            original_filename = data.get('original_filename', 'unknown')
            file_size = data.get('file_size', 0)
            file_hash = data.get('file_hash', '')

            if not encrypted_data:
                return Response({'error': 'No file data provided'}, status=400)

            if file_size > 104857600:  # 100MB
                return Response({'error': 'File too large'}, status=400)

            file_extension = os.path.splitext(original_filename)[1]
            encrypted_filename = f"enc_{uuid.uuid4()}{file_extension}"

            media_dir = os.path.join(settings.BASE_DIR, 'media', 'encrypted_files')
            os.makedirs(media_dir, exist_ok=True)

            file_path = os.path.join(media_dir, encrypted_filename)

            try:
                file_content = base64.b64decode(encrypted_data)
                with open(file_path, 'wb') as f:
                    f.write(file_content)
            except Exception as e:
                return Response({
                    'error': f'Failed to save file: {str(e)}'
                }, status=500)

            # Save to database with AUTHENTICATED user
            file_record = EncryptedFile.objects.create(
                owner=user,
                original_filename=original_filename,
                encrypted_filename=encrypted_filename,
                file_size=file_size,
                file_hash=file_hash,
                encryption_metadata=encryption_metadata
            )

            AuditLog.log_event(
                action='FILE_UPLOADED',
                user=user,
                details={
                    'filename': original_filename,
                    'size': file_size,
                    'file_id': str(file_record.id)
                },
                request=request,
                severity='LOW'
            )

            return Response({
                'id': str(file_record.id),
                'message': 'File uploaded successfully',
                'original_filename': original_filename,
                'uploaded_at': file_record.uploaded_at.isoformat()
            }, status=201)

        except Exception as e:
            import traceback
            print(f"Upload error: {traceback.format_exc()}")
            return Response({
                'error': f'Upload failed: {str(e)}'
            }, status=500)


class FileDownloadView(APIView):
    def get(self, request, file_id):
        try:
            # Get authenticated user
            user = get_authenticated_user(request)
            
            # Get file record
            try:
                file_record = EncryptedFile.objects.get(id=file_id, is_deleted=False)
            except EncryptedFile.DoesNotExist:
                return Response({'error': 'File not found'}, status=404)

            # Check permissions
            has_permission = False
            if user:
                # Check if user is owner
                if file_record.owner == user:
                    has_permission = True
                else:
                    # Check if file is shared with user
                    try:
                        share = FileShare.objects.get(
                            file=file_record,
                            shared_with=user,
                            is_revoked=False
                        )
                        if not share.is_expired() and share.can_download:
                            has_permission = True
                    except FileShare.DoesNotExist:
                        pass
            
            if not has_permission:
                if user:
                    AuditLog.log_event(
                        action='UNAUTHORIZED_ACCESS',
                        user=user,
                        details={
                            'file_id': str(file_id),
                            'filename': file_record.original_filename,
                            'reason': 'No permission to download'
                        },
                        request=request,
                        severity='HIGH'
                    )
                return Response({'error': 'Access denied'}, status=403)

            # Get file path
            file_path = os.path.join(
                settings.BASE_DIR,
                'media',
                'encrypted_files',
                file_record.encrypted_filename
            )

            if not os.path.exists(file_path):
                return Response({'error': 'File not found on disk'}, status=404)

            # Read encrypted file
            try:
                with open(file_path, 'rb') as f:
                    file_content = f.read()
            except Exception as e:
                return Response({
                    'error': f'Failed to read file: {str(e)}'
                }, status=500)

            # Encode to base64
            try:
                encoded_content = base64.b64encode(file_content).decode('utf-8')
            except Exception as e:
                return Response({
                    'error': f'Failed to encode file: {str(e)}'
                }, status=500)

            # Log download
            try:
                AuditLog.log_event(
                    action='FILE_DOWNLOADED',
                    user=user,
                    details={
                        'filename': file_record.original_filename,
                        'file_id': str(file_id),
                        'file_size': file_record.file_size
                    },
                    request=request,
                    severity='LOW'
                )
            except Exception as e:
                print(f"Audit log error: {e}")

            # Return encrypted data with metadata
            return Response({
                'encrypted_data': encoded_content,
                'original_filename': file_record.original_filename,
                'file_hash': file_record.file_hash,
                'encryption_metadata': file_record.encryption_metadata,
                'file_size': file_record.file_size
            }, status=200)

        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            print(f"Download error: {error_trace}")
            
            return Response({
                'error': f'Download failed: {str(e)}'
            }, status=500)


class FileDeleteView(APIView):
    def delete(self, request, file_id):
        try:
            # Get authenticated user
            user = get_authenticated_user(request)
            if not user:
                return Response({
                    'error': 'Authentication required'
                }, status=401)

            try:
                file_record = EncryptedFile.objects.get(id=file_id)
            except EncryptedFile.DoesNotExist:
                return Response({'error': 'File not found'}, status=404)

            # Check if user owns the file
            if file_record.owner != user:
                return Response({
                    'error': 'You do not have permission to delete this file'
                }, status=403)

            file_record.is_deleted = True
            file_record.save()

            AuditLog.log_event(
                action='FILE_DELETED',
                user=user,
                details={
                    'filename': file_record.original_filename,
                    'file_id': str(file_id)
                },
                request=request,
                severity='LOW'
            )

            return Response({'message': 'File deleted successfully'}, status=200)

        except Exception as e:
            return Response({'error': str(e)}, status=500)


class ShareFileView(APIView):
    def post(self, request, file_id):
        try:
            user = get_authenticated_user(request)
            if not user:
                return Response({'error': 'Authentication required'}, status=401)

            try:
                file = EncryptedFile.objects.get(id=file_id, is_deleted=False)
            except EncryptedFile.DoesNotExist:
                return Response({'error': 'File not found'}, status=404)

            is_owner = file.owner == user
            can_share = False

            if not is_owner:
                try:
                    share = FileShare.objects.get(file=file, shared_with=user, is_revoked=False)
                    can_share = share.can_reshare
                except FileShare.DoesNotExist:
                    can_share = False
            else:
                can_share = True

            if not can_share:
                return Response({'error': 'You do not have permission to share this file'}, status=403)

            shared_with_email = request.data.get('shared_with_email')
            can_download = request.data.get('can_download', True)
            can_reshare = request.data.get('can_reshare', False)
            expires_at = request.data.get('expires_at')

            if not shared_with_email:
                return Response({'error': 'Recipient email required'}, status=400)

            try:
                recipient = User.objects.get(email=shared_with_email)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=404)

            if FileShare.objects.filter(file=file, shared_with=recipient).exists():
                return Response({'error': 'File already shared with this user'}, status=400)

            expires_datetime = None
            if expires_at:
                from datetime import datetime
                expires_datetime = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))

            share = FileShare.objects.create(
                file=file,
                shared_by=user,
                shared_with=recipient,
                can_download=can_download,
                can_reshare=can_reshare,
                expires_at=expires_datetime
            )

            AuditLog.log_event(
                action='FILE_SHARED',
                user=user,
                details={
                    'filename': file.original_filename,
                    'shared_with': recipient.email,
                    'permissions': {'can_download': can_download, 'can_reshare': can_reshare}
                },
                request=request,
                severity='LOW'
            )

            return Response({
                'message': 'File shared successfully',
                'share_id': share.id,
                'shared_with': recipient.username,
                'can_download': can_download,
                'can_reshare': can_reshare,
                'expires_at': expires_datetime.isoformat() if expires_datetime else None
            }, status=201)

        except Exception as e:
            return Response({'error': str(e)}, status=500)


class SharedWithMeView(APIView):
    def get(self, request):
        try:
            user = get_authenticated_user(request)
            if not user:
                return Response({'error': 'Authentication required'}, status=401)

            shares = FileShare.objects.filter(
                shared_with=user,
                is_revoked=False,
                file__is_deleted=False
            ).select_related('file', 'shared_by')

            shared_files = []
            for share in shares:
                if not share.is_expired():
                    shared_files.append({
                        'id': str(share.file.id),
                        'original_filename': share.file.original_filename,
                        'file_size': share.file.file_size,
                        'shared_by': share.shared_by.username,
                        'shared_at': share.shared_at.isoformat(),
                        'can_download': share.can_download,
                        'can_reshare': share.can_reshare,
                        'expires_at': share.expires_at.isoformat() if share.expires_at else None,
                        'file_hash': share.file.file_hash,
                        'encryption_metadata': share.file.encryption_metadata
                    })

            return Response({'shared_files': shared_files}, status=200)

        except Exception as e:
            return Response({'error': str(e)}, status=500)


class RevokeShareView(APIView):
    def post(self, request, file_id):
        try:
            user = get_authenticated_user(request)
            if not user:
                return Response({'error': 'Authentication required'}, status=401)

            try:
                file = EncryptedFile.objects.get(id=file_id)
            except EncryptedFile.DoesNotExist:
                return Response({'error': 'File not found'}, status=404)

            if file.owner != user:
                return Response({'error': 'Only file owner can revoke shares'}, status=403)

            shared_with_email = request.data.get('shared_with_email')
            if not shared_with_email:
                return Response({'error': 'Recipient email required'}, status=400)

            try:
                recipient = User.objects.get(email=shared_with_email)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=404)

            try:
                share = FileShare.objects.get(file=file, shared_with=recipient)
                share.is_revoked = True
                share.save()

                AuditLog.log_event(
                    action='SHARE_REVOKED',
                    user=user,
                    details={
                        'filename': file.original_filename,
                        'revoked_for': recipient.email
                    },
                    request=request,
                    severity='MEDIUM'
                )

                return Response({'message': 'Share revoked successfully'}, status=200)

            except FileShare.DoesNotExist:
                return Response({'error': 'Share not found'}, status=404)

        except Exception as e:
            return Response({'error': str(e)}, status=500)


class FileSharesView(APIView):
    def get(self, request, file_id):
        try:
            user = get_authenticated_user(request)
            if not user:
                return Response({'error': 'Authentication required'}, status=401)

            try:
                file = EncryptedFile.objects.get(id=file_id)
            except EncryptedFile.DoesNotExist:
                return Response({'error': 'File not found'}, status=404)

            if file.owner != user:
                return Response({'error': 'Only file owner can view shares'}, status=403)

            shares = FileShare.objects.filter(file=file).select_related('shared_with')

            share_list = []
            for share in shares:
                share_list.append({
                    'shared_with': share.shared_with.username,
                    'shared_with_email': share.shared_with.email,
                    'shared_at': share.shared_at.isoformat(),
                    'can_download': share.can_download,
                    'can_reshare': share.can_reshare,
                    'expires_at': share.expires_at.isoformat() if share.expires_at else None,
                    'is_revoked': share.is_revoked,
                    'is_expired': share.is_expired()
                })

            return Response({'shares': share_list}, status=200)

        except Exception as e:
            return Response({'error': str(e)}, status=500)
