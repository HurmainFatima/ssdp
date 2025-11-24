/* eslint-disable no-undef */
import React, { useState } from 'react';
import api from "../api/client";
import { FileEncryption } from '../services/encryption';

const FileUpload = ({ onUploadSuccess }) => {
  const [file, setFile] = useState(null);
  const [password, setPassword] = useState('');
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');

  const handleFileSelect = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile) {
      // Validate file size (100 MB limit)
      if (selectedFile.size > 104857600) {
        setError('File size must be less than 100 MB');
        return;
      }
      setFile(selectedFile);
      setError('');
    }
  };

  const handleUpload = async () => {
  if (!file || !password) {
    setError('Please select a file and enter encryption password');
    return;
  }

  if (password.length < 12) {
    setError('Encryption password must be at least 12 characters');
    return;
  }

  // Get authentication token BEFORE try block
  const token = localStorage.getItem('accessToken');
  if (!token) {
    setError('Authentication required. Please login again.');
    return;
  }

  try {
    setUploading(true);
    setError('');
    setStatus('Encrypting file...');
    setProgress(20);

    // Encrypt file on client side
    const encryptedData = await FileEncryption.encryptFile(file, password);
    setProgress(50);
    setStatus('Uploading encrypted file...');

    // Upload to server with authentication
    const response = await api.post("files/upload/", {
  encrypted_data: encryptedData.encryptedData,
  encryption_metadata: {
    iv: encryptedData.iv,
    salt: encryptedData.salt,
  },
  original_filename: encryptedData.originalName,
  file_size: encryptedData.size,
  file_hash: encryptedData.hash,
});

    setProgress(100);
    setStatus('✅ File uploaded successfully!');
    
    // Reset form
    setTimeout(() => {
  console.log('🎉 Upload complete, calling callback...');
  setFile(null);
  setPassword('');
  setProgress(0);
  setStatus('');
  setUploading(false);
  if (onUploadSuccess) {
    console.log('✅ Callback exists, calling it now...');
    onUploadSuccess();
  } else {
    console.log('❌ No callback provided!');
  }
  
  document.getElementById('file-upload').value = '';
}, 2000);

  } catch (err) {
    if (err.response?.status === 401) {
      setError('Session expired. Please login again.');
    } else if (err.response?.status === 403) {
      setError('You do not have permission to upload files.');
    } else {
      setError(err.response?.data?.error || err.message || 'Upload failed. Please try again.');
    }
    setUploading(false);
    setProgress(0);
    setStatus('');
  }
};

  return (
    <div style={{ background: 'white', borderRadius: '12px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', padding: '24px' }}>
      <h2 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '20px', display: 'flex', alignItems: 'center' }}>
        📤 Upload Encrypted File
      </h2>

      <div style={{ marginBottom: '16px' }}>
        <label style={{ display: 'block', fontSize: '14px', fontWeight: '500', marginBottom: '8px' }}>
          Select File
        </label>
        <div style={{ border: '2px dashed #D1D5DB', borderRadius: '8px', padding: '24px', textAlign: 'center', cursor: 'pointer' }}>
          <input
            type="file"
            onChange={handleFileSelect}
            style={{ display: 'none' }}
            id="file-upload"
            disabled={uploading}
          />
          <label htmlFor="file-upload" style={{ cursor: 'pointer' }}>
            <div style={{ fontSize: '48px', marginBottom: '8px' }}>📁</div>
            <p style={{ color: '#6B7280' }}>
              {file ? file.name : 'Click to select file or drag and drop'}
            </p>
            {file && (
              <p style={{ fontSize: '14px', color: '#9CA3AF', marginTop: '4px' }}>
                Size: {(file.size / 1024 / 1024).toFixed(2)} MB
              </p>
            )}
          </label>
        </div>
      </div>

      <div style={{ marginBottom: '16px' }}>
        <label style={{ display: 'block', fontSize: '14px', fontWeight: '500', marginBottom: '8px' }}>
          Encryption Password (Min. 12 characters)
        </label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={{ width: '100%', padding: '12px', border: '1px solid #D1D5DB', borderRadius: '8px' }}
          placeholder="Enter strong encryption password"
          disabled={uploading}
          minLength="12"
        />
        <p style={{ fontSize: '12px', color: '#6B7280', marginTop: '4px' }}>
          ⚠️ Remember this password - required to decrypt your file later
        </p>
      </div>

      {uploading && (
        <div style={{ marginBottom: '16px' }}>
          <div style={{ width: '100%', height: '8px', background: '#E5E7EB', borderRadius: '4px', overflow: 'hidden' }}>
            <div
              style={{ 
                width: `${progress}%`, 
                height: '100%', 
                background: '#4F46E5', 
                transition: 'width 0.5s'
              }}
            />
          </div>
          <p style={{ fontSize: '14px', color: '#6B7280', marginTop: '8px', textAlign: 'center' }}>{status}</p>
        </div>
      )}

      {error && (
        <div style={{ background: '#FEF2F2', border: '1px solid #FEE2E2', color: '#991B1B', padding: '12px', borderRadius: '8px', marginBottom: '16px', display: 'flex', alignItems: 'center' }}>
          <span style={{ marginRight: '8px' }}>⚠️</span>
          {error}
        </div>
      )}

      {status && !uploading && (
        <div style={{ background: '#ECFDF5', border: '1px solid #D1FAE5', color: '#065F46', padding: '12px', borderRadius: '8px', marginBottom: '16px', display: 'flex', alignItems: 'center' }}>
          {status}
        </div>
      )}

      <button
        onClick={handleUpload}
        disabled={!file || !password || uploading}
        style={{ 
          width: '100%', 
          background: uploading ? '#9CA3AF' : '#4F46E5', 
          color: 'white', 
          padding: '12px', 
          borderRadius: '8px', 
          fontWeight: '600', 
          border: 'none', 
          cursor: uploading || !file || !password ? 'not-allowed' : 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}
      >
        <span style={{ marginRight: '8px' }}>🔒</span>
        {uploading ? 'Encrypting & Uploading...' : 'Encrypt & Upload'}
      </button>

      <div style={{ marginTop: '20px', background: '#EFF6FF', border: '1px solid #DBEAFE', borderRadius: '8px', padding: '16px' }}>
        <h3 style={{ fontWeight: '600', color: '#1E40AF', marginBottom: '8px', fontSize: '14px' }}>🔐 Client-Side Encryption</h3>
        <ul style={{ fontSize: '13px', color: '#1E3A8A', paddingLeft: '20px', margin: 0 }}>
          <li>Files encrypted with AES-256 in your browser</li>
          <li>Your encryption password never leaves your device</li>
          <li>Server stores only encrypted data</li>
          <li>SHA-256 hash ensures file integrity</li>
        </ul>
      </div>
    </div>
  );
};

export default FileUpload;
