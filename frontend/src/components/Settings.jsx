import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from "../services/client";

const Settings = () => {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [showMfaSetup, setShowMfaSetup] = useState(false);
  const [qrCode, setQrCode] = useState('');
  const [secret, setSecret] = useState('');
  const [mfaToken, setMfaToken] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    loadUserProfile();
  }, []);

  const loadUserProfile = async () => {
    try {
      const response = await api.get("auth/profile/");
      setUser(response.data);
      setMfaEnabled(response.data.mfa_enabled);
    } catch (err) {
      console.error('Failed to load profile:', err);
    }
  };

  const handleEnableMFA = async () => {
    try {
      setLoading(true);
      setError('');

      const response = await api.post("auth/mfa/enable/");
      
      setQrCode(response.data.qr_code);
      setSecret(response.data.secret);
      setShowMfaSetup(true);
      setMessage('');
    } catch (err) {
      setError('Failed to enable MFA: ' + (err.response?.data?.error || err.message));
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyMFA = async () => {
    try {
      setLoading(true);
      setError('');
      
      const response = await api.post("auth/mfa/verify/", { mfa_token: mfaToken });
      
      setMessage('✅ MFA enabled successfully!');
      setMfaEnabled(true);
      setShowMfaSetup(false);
      setMfaToken('');
      
      // Update user in localStorage
      const userData = JSON.parse(localStorage.getItem('user'));
      userData.mfa_enabled = true;
      localStorage.setItem('user', JSON.stringify(userData));
    } catch (err) {
      setError('Invalid MFA token. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleDisableMFA = async () => {
    if (!window.confirm('Are you sure you want to disable MFA? This will make your account less secure.')) return;

    try {
      setLoading(true);
      setError('');

      await api.post("auth/mfa/disable/", { password });
      
      setMessage('✅ MFA disabled successfully');
      setMfaEnabled(false);
      setPassword('');
      
      // Update user in localStorage
      const userData = JSON.parse(localStorage.getItem('user'));
      userData.mfa_enabled = false;
      localStorage.setItem('user', JSON.stringify(userData));
    } catch (err) {
      setError('Failed to disable MFA: ' + (err.response?.data?.error || err.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', background: '#F9FAFB' }}>
      {/* Header */}
      <header style={{ background: 'white', boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.1)', padding: '16px 32px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', maxWidth: '1400px', margin: '0 auto' }}>
          <h1 style={{ fontSize: '24px', fontWeight: 'bold', color: '#111827', display: 'flex', alignItems: 'center' }}>
            <span style={{ fontSize: '28px', marginRight: '8px' }}>⚙️</span>
            Settings
          </h1>
          <button
            onClick={() => navigate('/dashboard')}
            style={{ padding: '8px 16px', background: '#4F46E5', color: 'white', borderRadius: '6px', border: 'none', cursor: 'pointer', fontWeight: '500' }}
          >
            ← Back to Dashboard
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main style={{ maxWidth: '800px', margin: '0 auto', padding: '32px' }}>
        {/* User Profile Card */}
        <div style={{ background: 'white', borderRadius: '12px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', padding: '24px', marginBottom: '24px' }}>
          <h2 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '16px' }}>👤 Profile Information</h2>
          {user && (
            <div style={{ display: 'grid', gridTemplateColumns: '150px 1fr', gap: '12px', fontSize: '14px' }}>
              <div style={{ color: '#6B7280', fontWeight: '500' }}>Username:</div>
              <div style={{ color: '#111827' }}>{user.username}</div>
              
              <div style={{ color: '#6B7280', fontWeight: '500' }}>Email:</div>
              <div style={{ color: '#111827' }}>{user.email}</div>
              
              <div style={{ color: '#6B7280', fontWeight: '500' }}>Role:</div>
              <div style={{ color: '#111827' }}>{user.role}</div>
              
              <div style={{ color: '#6B7280', fontWeight: '500' }}>Member Since:</div>
              <div style={{ color: '#111827' }}>{new Date(user.date_joined).toLocaleDateString()}</div>
            </div>
          )}
        </div>

        {/* MFA Settings Card */}
        {/* ... The rest of your component stays unchanged ... */}
      </main>
    </div>
  );
};

export default Settings;
