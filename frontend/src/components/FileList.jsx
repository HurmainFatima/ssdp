import React, { useState, useEffect } from 'react';
import api from '../services/client';
import { FileEncryption } from '../services/encryption';

const FileList = ({ refreshTrigger }) => {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [downloadingFile, setDownloadingFile] = useState(null);
  const [decryptPassword, setDecryptPassword] = useState('');
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);

  // Share modal states
  const [showShareModal, setShowShareModal] = useState(false);
  const [shareEmail, setShareEmail] = useState('');
  const [canDownload, setCanDownload] = useState(true);
  const [canReshare, setCanReshare] = useState(false);
  const [expiresAt, setExpiresAt] = useState('');
  const [sharingFile, setSharingFile] = useState(false);

  // View shares modal
  const [showSharesModal, setShowSharesModal] = useState(false);
  const [fileShares, setFileShares] = useState([]);

  useEffect(() => {
    console.log('🔍 FileList effect triggered, refreshTrigger =', refreshTrigger);
    loadFiles();
  }, [refreshTrigger]);

  const loadFiles = async () => {
    try {
      console.log('📡 Loading files...');
      setLoading(true);
      const token = localStorage.getItem('accessToken');
      if (!token) {
        setError('Authentication required. Please login again.');
        setLoading(false);
        return;
      }

      const response = await api.get('files/', {
        headers: { Authorization: `Bearer ${token}` },
      });

      console.log('✅ Files loaded:', response.data.files.length, 'files');
      setFiles(response.data.files || []);
      setError('');
    } catch (err) {
      if (err.response?.status === 401) {
        setError('Session expired. Please login again.');
      } else {
        setError('Failed to load files: ' + (err.response?.data?.error || err.message));
      }
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadClick = (file) => {
    setSelectedFile(file);
    setShowPasswordModal(true);
    setDecryptPassword('');
  };

  const handleDownload = async () => {
    if (!decryptPassword) {
      alert('Please enter decryption password');
      return;
    }

    try {
      setDownloadingFile(selectedFile.id);
      const token = localStorage.getItem('accessToken');

      const response = await api.get(`files/${selectedFile.id}/download/`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      const { encrypted_data, original_filename, file_hash, encryption_metadata } = response.data;

      const decryptedData = FileEncryption.decryptFile(
        encrypted_data,
        decryptPassword,
        encryption_metadata
      );

      const isValid = FileEncryption.verifyIntegrity(decryptedData, file_hash);
      if (!isValid) {
        alert('⚠️ File integrity check failed! File may be corrupted or tampered.');
        setDownloadingFile(null);
        return;
      }

      const filenameParts = original_filename.split('.');
      const fileExtension = filenameParts.length > 1 ? filenameParts.pop().toLowerCase() : '';
      const mimeTypes = {
        png: 'image/png',
        jpg: 'image/jpeg',
        jpeg: 'image/jpeg',
        gif: 'image/gif',
        pdf: 'application/pdf',
        txt: 'text/plain',
        ps1: 'text/plain',
        zip: 'application/zip',
        doc: 'application/msword',
        docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      };
      const safeExtension = typeof fileExtension === 'string' ? fileExtension.toLowerCase() : '';
      const mimeType = mimeTypes[safeExtension] || 'application/octet-stream';

      const blob = new Blob([decryptedData], { type: mimeType });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = original_filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      alert('✅ File downloaded and verified successfully!');
      setShowPasswordModal(false);
      setDecryptPassword('');
      setSelectedFile(null);
    } catch (err) {
      if (err.response?.status === 401) {
        alert('❌ Session expired. Please login again.');
      } else if (err.response?.status === 403) {
        alert('❌ Access denied. You do not have permission to download this file.');
      } else {
        alert('❌ Decryption failed. Check your password and try again.');
      }
      console.error(err);
    } finally {
      setDownloadingFile(null);
    }
  };

  const handleDelete = async (fileId) => {
    if (!window.confirm('Are you sure you want to delete this file?')) return;

    try {
      const token = localStorage.getItem('accessToken');

      await api.delete(`files/${fileId}/`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      setFiles(files.filter((f) => f.id !== fileId));
      alert('File deleted successfully');
    } catch (err) {
      if (err.response?.status === 401) {
        alert('Session expired. Please login again.');
      } else if (err.response?.status === 403) {
        alert('Access denied. You do not have permission to delete this file.');
      } else {
        alert('Failed to delete file: ' + (err.response?.data?.error || err.message));
      }
    }
  };

  const handleShareClick = (file) => {
    setSelectedFile(file);
    setShowShareModal(true);
    setShareEmail('');
    setCanDownload(true);
    setCanReshare(false);
    setExpiresAt('');
  };

  const handleShare = async () => {
    if (!shareEmail) {
      alert('Please enter recipient email');
      return;
    }

    try {
      setSharingFile(true);
      const token = localStorage.getItem('accessToken');

      await api.post(
        `files/${selectedFile.id}/share/`,
        {
          shared_with_email: shareEmail,
          can_download: canDownload,
          can_reshare: canReshare,
          expires_at: expiresAt || null,
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      alert('✅ File shared successfully!');
      setShowShareModal(false);
      setSelectedFile(null);
    } catch (err) {
      if (err.response?.status === 401) {
        alert('Session expired. Please login again.');
      } else {
        alert('Failed to share file: ' + (err.response?.data?.error || err.message));
      }
    } finally {
      setSharingFile(false);
    }
  };

  const handleViewShares = async (file) => {
    try {
      const token = localStorage.getItem('accessToken');
      const response = await api.get(`files/${file.id}/shares/`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      setFileShares(response.data.shares || []);
      setSelectedFile(file);
      setShowSharesModal(true);
    } catch (err) {
      if (err.response?.status === 401) {
        alert('Session expired. Please login again.');
      } else {
        alert('Failed to load shares: ' + (err.response?.data?.error || err.message));
      }
    }
  };

  const handleRevokeShare = async (shareEmail) => {
    if (!window.confirm(`Revoke access for ${shareEmail}?`)) return;

    try {
      const token = localStorage.getItem('accessToken');
      await api.post(
        `files/${selectedFile.id}/revoke/`,
        { shared_with_email: shareEmail },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      alert('✅ Share revoked successfully');
      handleViewShares(selectedFile);
    } catch (err) {
      alert('Failed to revoke share: ' + (err.response?.data?.error || err.message));
    }
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
  };

  if (loading) {
    return (
      <div
        style={{
          background: 'white',
          borderRadius: '12px',
          boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
          padding: '24px',
          textAlign: 'center',
        }}
      >
        <div style={{ fontSize: '48px', marginBottom: '16px' }}>⏳</div>
        <p style={{ color: '#6B7280' }}>Loading files...</p>
      </div>
    );
  }

  return (
    <div style={{ background: 'white', borderRadius: '12px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', padding: '24px' }}>
      <h2 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '20px', display: 'flex', alignItems: 'center' }}>
        📁 Your Encrypted Files
      </h2>

      {error && (
        <div
          style={{
            background: '#FEF2F2',
            border: '1px solid #FEE2E2',
            color: '#991B1B',
            padding: '12px',
            borderRadius: '8px',
            marginBottom: '16px',
          }}
        >
          {error}
        </div>
      )}

      {files.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '40px 20px' }}>
          <div style={{ fontSize: '64px', marginBottom: '16px' }}>🔒</div>
          <p style={{ color: '#6B7280', fontSize: '16px' }}>No files yet. Upload your first encrypted file!</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {files.map((file) => (
            <div
              key={file.id}
              style={{
                border: '1px solid #E5E7EB',
                borderRadius: '8px',
                padding: '16px',
                transition: 'border-color 0.2s',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.borderColor = '#818CF8')}
              onMouseLeave={(e) => (e.currentTarget.style.borderColor = '#E5E7EB')}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
                    <span style={{ fontSize: '20px', marginRight: '8px' }}>📄</span>
                    <h3 style={{ fontSize: '16px', fontWeight: '600', color: '#111827', margin: 0 }}>
                      {file.original_filename}
                    </h3>
                  </div>
                  <div style={{ display: 'flex', gap: '16px', fontSize: '14px', color: '#6B7280' }}>
                    <span>📦 {(file.file_size / 1024 / 1024).toFixed(2)} MB</span>
                    <span>👤 {file.owner}</span>
                    <span>📅 {formatDate(file.uploaded_at)}</span>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    onClick={() => handleDownloadClick(file)}
                    disabled={downloadingFile === file.id}
                    style={{
                      padding: '8px 16px',
                      background: downloadingFile === file.id ? '#9CA3AF' : '#4F46E5',
                      color: 'white',
                      border: 'none',
                      borderRadius: '6px',
                      cursor: downloadingFile === file.id ? 'not-allowed' : 'pointer',
                      fontWeight: '500',
                      fontSize: '14px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                    }}
                  >
                    <span>{downloadingFile === file.id ? '⏳' : '⬇️'}</span>
                    {downloadingFile === file.id ? 'Downloading...' : 'Download'}
                  </button>

                  <button
                    onClick={() => handleShareClick(file)}
                    style={{
                      padding: '8px 16px',
                      background: '#10B981',
                      color: 'white',
                      border: 'none',
                      borderRadius: '6px',
                      cursor: 'pointer',
                      fontWeight: '500',
                      fontSize: '14px',
                    }}
                  >
                    👥 Share
                  </button>

                  <button
                    onClick={() => handleViewShares(file)}
                    style={{
                      padding: '8px 16px',
                      background: '#6B7280',
                      color: 'white',
                      border: 'none',
                      borderRadius: '6px',
                      cursor: 'pointer',
                      fontWeight: '500',
                      fontSize: '14px',
                    }}
                  >
                    👁️ Shares
                  </button>

                  <button
                    onClick={() => handleDelete(file.id)}
                    style={{
                      padding: '8px 16px',
                      background: '#EF4444',
                      color: 'white',
                      border: 'none',
                      borderRadius: '6px',
                      cursor: 'pointer',
                      fontWeight: '500',
                      fontSize: '14px',
                    }}
                  >
                    🗑️ Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}


      {/* Share Modal */}
      {showShareModal && (
        <div style={{ 
          position: 'fixed', 
          top: 0, 
          left: 0, 
          right: 0, 
          bottom: 0, 
          background: 'rgba(0,0,0,0.5)', 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'center',
          zIndex: 1000
        }}>
          <div style={{ 
            background: 'white', 
            borderRadius: '12px', 
            padding: '24px', 
            maxWidth: '500px', 
            width: '90%',
            boxShadow: '0 20px 25px -5px rgba(0,0,0,0.1)'
          }}>
            <h3 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '16px' }}>
              👥 Share File
            </h3>
            <p style={{ fontSize: '14px', color: '#6B7280', marginBottom: '16px' }}>
              Share <strong>{selectedFile?.original_filename}</strong> with another user
            </p>
            
            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '14px', fontWeight: '500', marginBottom: '8px' }}>
                Recipient Email:
              </label>
              <input
                type="email"
                value={shareEmail}
                onChange={(e) => setShareEmail(e.target.value)}
                placeholder="user@example.com"
                style={{ 
                  width: '100%', 
                  padding: '12px', 
                  border: '1px solid #D1D5DB', 
                  borderRadius: '8px'
                }}
              />
            </div>

            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'flex', alignItems: 'center', marginBottom: '8px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={canDownload}
                  onChange={(e) => setCanDownload(e.target.checked)}
                  style={{ marginRight: '8px' }}
                />
                <span style={{ fontSize: '14px' }}>Allow recipient to download</span>
              </label>
              
              <label style={{ display: 'flex', alignItems: 'center', marginBottom: '8px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={canReshare}
                  onChange={(e) => setCanReshare(e.target.checked)}
                  style={{ marginRight: '8px' }}
                />
                <span style={{ fontSize: '14px' }}>Allow recipient to re-share</span>
              </label>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '14px', fontWeight: '500', marginBottom: '8px' }}>
                Expiration Date (Optional):
              </label>
              <input
                type="datetime-local"
                value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)}
                style={{ 
                  width: '100%', 
                  padding: '12px', 
                  border: '1px solid #D1D5DB', 
                  borderRadius: '8px'
                }}
              />
            </div>

            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                onClick={() => {
                  setShowShareModal(false);
                  setSelectedFile(null);
                }}
                style={{ 
                  flex: 1,
                  padding: '12px', 
                  background: '#F3F4F6', 
                  color: '#374151', 
                  border: 'none', 
                  borderRadius: '8px', 
                  cursor: 'pointer',
                  fontWeight: '500'
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleShare}
                disabled={!shareEmail || sharingFile}
                style={{ 
                  flex: 1,
                  padding: '12px', 
                  background: shareEmail && !sharingFile ? '#10B981' : '#9CA3AF', 
                  color: 'white', 
                  border: 'none', 
                  borderRadius: '8px', 
                  cursor: shareEmail && !sharingFile ? 'pointer' : 'not-allowed',
                  fontWeight: '500'
                }}
              >
                {sharingFile ? 'Sharing...' : 'Share File'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* View Shares Modal */}
      {showSharesModal && (
        <div style={{ 
          position: 'fixed', 
          top: 0, 
          left: 0, 
          right: 0, 
          bottom: 0, 
          background: 'rgba(0,0,0,0.5)', 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'center',
          zIndex: 1000
        }}>
          <div style={{ 
            background: 'white', 
            borderRadius: '12px', 
            padding: '24px', 
            maxWidth: '600px', 
            width: '90%',
            maxHeight: '80vh',
            overflow: 'auto',
            boxShadow: '0 20px 25px -5px rgba(0,0,0,0.1)'
          }}>
            <h3 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '16px' }}>
              👁️ File Shares
            </h3>
            <p style={{ fontSize: '14px', color: '#6B7280', marginBottom: '16px' }}>
              Users who have access to: <strong>{selectedFile?.original_filename}</strong>
            </p>
            
            {fileShares.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '20px', color: '#6B7280' }}>
                This file hasn't been shared with anyone yet.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {fileShares.map((share, index) => (
                  <div
                    key={index}
                    style={{ 
                      border: '1px solid #E5E7EB', 
                      borderRadius: '8px', 
                      padding: '16px',
                      background: share.is_revoked ? '#F3F4F6' : 'white'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontWeight: '600', marginBottom: '4px' }}>
                          {share.shared_with} ({share.shared_with_email})
                        </div>
                        <div style={{ fontSize: '13px', color: '#6B7280' }}>
                          Shared: {new Date(share.shared_at).toLocaleDateString()}
                        </div>
                        <div style={{ fontSize: '13px', marginTop: '8px', display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                          {share.can_download && <span style={{ color: '#10B981' }}>✅ Can Download</span>}
                          {share.can_reshare && <span style={{ color: '#3B82F6' }}>🔄 Can Re-share</span>}
                          {share.is_revoked && <span style={{ color: '#EF4444' }}>❌ Revoked</span>}
                          {share.is_expired && <span style={{ color: '#F59E0B' }}>⏰ Expired</span>}
                          {share.expires_at && !share.is_expired && (
                            <span style={{ color: '#F59E0B' }}>
                              ⏰ Expires: {new Date(share.expires_at).toLocaleDateString()}
                            </span>
                          )}
                        </div>
                      </div>
                      
                      {!share.is_revoked && (
                        <button
                          onClick={() => handleRevokeShare(share.shared_with_email)}
                          style={{ 
                            padding: '6px 12px', 
                            background: '#EF4444', 
                            color: 'white', 
                            border: 'none', 
                            borderRadius: '6px', 
                            cursor: 'pointer',
                            fontSize: '12px',
                            fontWeight: '500'
                          }}
                        >
                          Revoke
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}

            <button
              onClick={() => {
                setShowSharesModal(false);
                setSelectedFile(null);
              }}
              style={{ 
                width: '100%',
                marginTop: '16px',
                padding: '12px', 
                background: '#F3F4F6', 
                color: '#374151', 
                border: 'none', 
                borderRadius: '8px', 
                cursor: 'pointer',
                fontWeight: '500'
              }}
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default FileList;
