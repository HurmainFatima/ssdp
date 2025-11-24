import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

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
      const token = localStorage.getItem('accessToken');
      const response = await axios.get('http://localhost:8000/api/auth/profile/', {
        headers: { Authorization: `Bearer ${token}` }
      });
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
      const token = localStorage.getItem('accessToken');
      
      const response = await axios.post(
        'http://localhost:8000/api/auth/mfa/enable/',
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
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
      const token = localStorage.getItem('accessToken');
      
      const response = await axios.post(
        'http://localhost:8000/api/auth/mfa/verify/',
        { mfa_token: mfaToken },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
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
    if (!window.confirm('Are you sure you want to disable MFA? This will make your account less secure.')) {
      return;
    }

    try {
      setLoading(true);
      setError('');
      const token = localStorage.getItem('accessToken');
      
      await axios.post(
        'http://localhost:8000/api/auth/mfa/disable/',
        { password },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
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
        <div style={{ background: 'white', borderRadius: '12px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', padding: '24px' }}>
          <h2 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '16px' }}>🔐 Multi-Factor Authentication (MFA)</h2>
          
          {message && (
            <div style={{ background: '#ECFDF5', border: '1px solid #D1FAE5', color: '#065F46', padding: '12px', borderRadius: '8px', marginBottom: '16px' }}>
              {message}
            </div>
          )}

          {error && (
            <div style={{ background: '#FEF2F2', border: '1px solid #FEE2E2', color: '#991B1B', padding: '12px', borderRadius: '8px', marginBottom: '16px' }}>
              {error}
            </div>
          )}

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', padding: '16px', background: '#F9FAFB', borderRadius: '8px' }}>
            <div>
              <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '4px' }}>
                Status: {mfaEnabled ? '✅ Enabled' : '⚠️ Disabled'}
              </h3>
              <p style={{ fontSize: '14px', color: '#6B7280' }}>
                {mfaEnabled 
                  ? 'Your account is protected with two-factor authentication'
                  : 'Enable MFA to add an extra layer of security to your account'}
              </p>
            </div>
            
            {!mfaEnabled ? (
              <button
                onClick={handleEnableMFA}
                disabled={loading}
                style={{ 
                  padding: '10px 20px', 
                  background: '#10B981', 
                  color: 'white', 
                  borderRadius: '6px', 
                  border: 'none', 
                  cursor: loading ? 'not-allowed' : 'pointer', 
                  fontWeight: '500',
                  whiteSpace: 'nowrap'
                }}
              >
                {loading ? 'Loading...' : 'Enable MFA'}
              </button>
            ) : (
              <button
                onClick={() => setShowMfaSetup(true)}
                style={{ 
                  padding: '10px 20px', 
                  background: '#EF4444', 
                  color: 'white', 
                  borderRadius: '6px', 
                  border: 'none', 
                  cursor: 'pointer', 
                  fontWeight: '500',
                  whiteSpace: 'nowrap'
                }}
              >
                Disable MFA
              </button>
            )}
          </div>

          {/* MFA Setup Modal */}
          {showMfaSetup && !mfaEnabled && (
            <div style={{ border: '2px solid #818CF8', borderRadius: '12px', padding: '24px', background: '#EEF2FF' }}>
              <h3 style={{ fontSize: '18px', fontWeight: 'bold', marginBottom: '16px', color: '#4F46E5' }}>
                📱 Set Up Authenticator App
              </h3>
              
              <ol style={{ fontSize: '14px', color: '#374151', marginBottom: '20px', paddingLeft: '20px', lineHeight: '1.8' }}>
                <li>Download an authenticator app (Google Authenticator, Authy, Microsoft Authenticator)</li>
                <li>Scan the QR code below with your app</li>
                <li>Enter the 6-digit code from your app to verify</li>
              </ol>

              {qrCode && (
                <div style={{ textAlign: 'center', marginBottom: '20px' }}>
                  <img src={qrCode} alt="QR Code" style={{ maxWidth: '200px', border: '2px solid #E5E7EB', borderRadius: '8px', padding: '8px', background: 'white' }} />
                  <p style={{ fontSize: '12px', color: '#6B7280', marginTop: '8px' }}>
                    Secret Key: <code style={{ background: '#F3F4F6', padding: '2px 6px', borderRadius: '4px' }}>{secret}</code>
                  </p>
                </div>
              )}

              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: '500', marginBottom: '8px', color: '#374151' }}>
                  Enter 6-digit code from your app:
                </label>
                <input
                  type="text"
                  value={mfaToken}
                  onChange={(e) => setMfaToken(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="000000"
                  style={{ 
                    width: '100%', 
                    padding: '12px', 
                    border: '2px solid #D1D5DB', 
                    borderRadius: '8px',
                    fontSize: '18px',
                    textAlign: 'center',
                    letterSpacing: '4px'
                  }}
                  maxLength="6"
                />
              </div>

              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  onClick={() => {
                    setShowMfaSetup(false);
                    setMfaToken('');
                    setQrCode('');
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
                  onClick={handleVerifyMFA}
                  disabled={mfaToken.length !== 6 || loading}
                  style={{ 
                    flex: 1,
                    padding: '12px', 
                    background: mfaToken.length === 6 ? '#10B981' : '#9CA3AF', 
                    color: 'white', 
                    border: 'none', 
                    borderRadius: '8px', 
                    cursor: mfaToken.length === 6 && !loading ? 'pointer' : 'not-allowed',
                    fontWeight: '500'
                  }}
                >
                  {loading ? 'Verifying...' : 'Verify & Enable'}
                </button>
              </div>
            </div>
          )}

          {/* Disable MFA */}
          {showMfaSetup && mfaEnabled && (
            <div style={{ border: '2px solid #FCA5A5', borderRadius: '12px', padding: '24px', background: '#FEF2F2' }}>
              <h3 style={{ fontSize: '18px', fontWeight: 'bold', marginBottom: '16px', color: '#DC2626' }}>
                ⚠️ Disable Multi-Factor Authentication
              </h3>
              
              <p style={{ fontSize: '14px', color: '#991B1B', marginBottom: '16px' }}>
                Disabling MFA will make your account less secure. Enter your password to confirm.
              </p>

              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: '500', marginBottom: '8px' }}>
                  Password:
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  style={{ 
                    width: '100%', 
                    padding: '12px', 
                    border: '2px solid #FCA5A5', 
                    borderRadius: '8px'
                  }}
                />
              </div>

              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  onClick={() => {
                    setShowMfaSetup(false);
                    setPassword('');
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
                  onClick={handleDisableMFA}
                  disabled={!password || loading}
                  style={{ 
                    flex: 1,
                    padding: '12px', 
                    background: password ? '#EF4444' : '#9CA3AF', 
                    color: 'white', 
                    border: 'none', 
                    borderRadius: '8px', 
                    cursor: password && !loading ? 'pointer' : 'not-allowed',
                    fontWeight: '500'
                  }}
                >
                  {loading ? 'Disabling...' : 'Disable MFA'}
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Security Tips */}
        <div style={{ marginTop: '24px', background: '#FFFBEB', border: '1px solid #FCD34D', borderRadius: '12px', padding: '20px' }}>
          <h3 style={{ fontSize: '16px', fontWeight: 'bold', color: '#92400E', marginBottom: '12px' }}>
            💡 Security Best Practices
          </h3>
          <ul style={{ fontSize: '14px', color: '#78350F', paddingLeft: '20px', margin: 0, lineHeight: '1.8' }}>
            <li>Use a strong, unique password for your account</li>
            <li>Enable MFA for enhanced security</li>
            <li>Never share your authentication codes with anyone</li>
            <li>Keep your authenticator app backed up</li>
            <li>Log out from shared devices</li>
          </ul>
        </div>
      </main>
    </div>
  );
};

export default Settings;