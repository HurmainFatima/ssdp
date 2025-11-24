import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/client';
import { FileEncryption } from '../services/encryption';
import axios from 'axios';

const SharedFiles = () => {
  const navigate = useNavigate();
  const [sharedFiles, setSharedFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [downloadingFile, setDownloadingFile] = useState(null);
  const [decryptPassword, setDecryptPassword] = useState('');
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);

  useEffect(() => {
    loadSharedFiles();
  }, []);

 const loadSharedFiles = async () => {
  try {
    setLoading(true);
    const token = localStorage.getItem('accessToken');

    const response = await api.get("files/shared-with-me/", {
      headers: { Authorization: `Bearer ${token}` }
    });

    setSharedFiles(response.data.shared_files || []);
    setError('');
  } catch (err) {
    setError('Failed to load shared files');
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
      
      const response = await axios.get(
        `http://localhost:8000/api/files/${selectedFile.id}/download/`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      const { encrypted_data, original_filename, file_hash, encryption_metadata } = response.data;
      
      const decryptedData = FileEncryption.decryptFile(
        encrypted_data,
        decryptPassword,
        encryption_metadata
      );
      
      const isValid = FileEncryption.verifyIntegrity(decryptedData, file_hash);
      if (!isValid) {
        alert('⚠️ File integrity check failed! File may be corrupted.');
        setDownloadingFile(null);
        return;
      }
      
      // decryptedData is already a Uint8Array, create blob directly
      // Infer MIME type from filename extension
      const filenameParts = original_filename.split('.');
      const fileExtension = filenameParts.length > 1 ? filenameParts.pop().toLowerCase() : '';
      const mimeTypes = {
        'png': 'image/png',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'gif': 'image/gif',
        'pdf': 'application/pdf',
        'txt': 'text/plain',
        'ps1': 'text/plain',
        'zip': 'application/zip',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
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
      alert('❌ Decryption failed. Check your password and try again.');
      console.error(err);
    } finally {
      setDownloadingFile(null);
    }
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
  };

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', background: '#F9FAFB', padding: '32px' }}>
        <div style={{ maxWidth: '1400px', margin: '0 auto', textAlign: 'center' }}>
          <div style={{ fontSize: '48px', marginBottom: '16px' }}>⏳</div>
          <p style={{ color: '#6B7280' }}>Loading shared files...</p>
        </div>
      </div>
    );
  }

  return (
    <div style={{ minHeight: '100vh', background: '#F9FAFB' }}>
      <header style={{ background: 'white', boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.1)', padding: '16px 32px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', maxWidth: '1400px', margin: '0 auto' }}>
          <h1 style={{ fontSize: '24px', fontWeight: 'bold', color: '#111827' }}>
            <span style={{ fontSize: '28px', marginRight: '8px' }}>👥</span>
            Files Shared With Me
          </h1>
          <button
            onClick={() => navigate('/dashboard')}
            style={{ padding: '8px 16px', background: '#4F46E5', color: 'white', borderRadius: '6px', border: 'none', cursor: 'pointer', fontWeight: '500' }}
          >
            ← Back to Dashboard
          </button>
        </div>
      </header>

      <main style={{ maxWidth: '1400px', margin: '0 auto', padding: '32px' }}>
        {error && (
          <div style={{ background: '#FEF2F2', border: '1px solid #FEE2E2', color: '#991B1B', padding: '12px', borderRadius: '8px', marginBottom: '16px' }}>
            {error}
          </div>
        )}

        {sharedFiles.length === 0 ? (
          <div style={{ background: 'white', borderRadius: '12px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', padding: '60px', textAlign: 'center' }}>
            <div style={{ fontSize: '64px', marginBottom: '16px' }}>📭</div>
            <h2 style={{ fontSize: '20px', fontWeight: 'bold', color: '#111827', marginBottom: '8px' }}>
              No Files Shared With You
            </h2>
            <p style={{ color: '#6B7280' }}>
              When other users share files with you, they will appear here.
            </p>
          </div>
        ) : (
          <div style={{ background: 'white', borderRadius: '12px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', padding: '24px' }}>
            <h2 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '20px' }}>
              Shared Files ({sharedFiles.length})
            </h2>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {sharedFiles.map((file) => (
                <div
                  key={file.id}
                  style={{ 
                    border: '1px solid #E5E7EB', 
                    borderRadius: '8px', 
                    padding: '16px',
                    transition: 'border-color 0.2s',
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.borderColor = '#818CF8'}
                  onMouseLeave={(e) => e.currentTarget.style.borderColor = '#E5E7EB'}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
                        <span style={{ fontSize: '20px', marginRight: '8px' }}>📄</span>
                        <h3 style={{ fontSize: '16px', fontWeight: '600', color: '#111827', margin: 0 }}>
                          {file.original_filename}
                        </h3>
                      </div>
                      <div style={{ display: 'flex', gap: '16px', fontSize: '14px', color: '#6B7280', flexWrap: 'wrap' }}>
                        <span>📦 {(file.file_size / 1024 / 1024).toFixed(2)} MB</span>
                        <span>👤 Shared by: {file.shared_by}</span>
                        <span>📅 {formatDate(file.shared_at)}</span>
                        {file.can_download && <span style={{ color: '#10B981' }}>✅ Can Download</span>}
                        {file.can_reshare && <span style={{ color: '#3B82F6' }}>🔄 Can Re-share</span>}
                        {file.expires_at && (
                          <span style={{ color: '#F59E0B' }}>⏰ Expires: {formatDate(file.expires_at)}</span>
                        )}
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: '8px' }}>
                      {file.can_download && (
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
                            gap: '4px'
                          }}
                        >
                          <span>{downloadingFile === file.id ? '⏳' : '⬇️'}</span>
                          {downloadingFile === file.id ? 'Downloading...' : 'Download'}
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Password Modal */}
        {showPasswordModal && (
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
              maxWidth: '400px', 
              width: '90%',
              boxShadow: '0 20px 25px -5px rgba(0,0,0,0.1)'
            }}>
              <h3 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '16px' }}>
                🔓 Enter Decryption Password
              </h3>
              <p style={{ fontSize: '14px', color: '#6B7280', marginBottom: '16px' }}>
                Enter the password to decrypt: <strong>{selectedFile?.original_filename}</strong>
              </p>
              
              <input
                type="password"
                value={decryptPassword}
                onChange={(e) => setDecryptPassword(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleDownload()}
                placeholder="Enter decryption password"
                style={{ 
                  width: '100%', 
                  padding: '12px', 
                  border: '1px solid #D1D5DB', 
                  borderRadius: '8px',
                  marginBottom: '16px',
                  fontSize: '14px'
                }}
                autoFocus
              />

              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  onClick={() => {
                    setShowPasswordModal(false);
                    setDecryptPassword('');
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
                  onClick={handleDownload}
                  disabled={!decryptPassword}
                  style={{ 
                    flex: 1,
                    padding: '12px', 
                    background: decryptPassword ? '#4F46E5' : '#9CA3AF', 
                    color: 'white', 
                    border: 'none', 
                    borderRadius: '8px', 
                    cursor: decryptPassword ? 'pointer' : 'not-allowed',
                    fontWeight: '500'
                  }}
                >
                  Decrypt & Download
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

export default SharedFiles;
