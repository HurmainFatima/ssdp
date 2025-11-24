import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import FileUpload from './FileUpload';
import FileList from './FileList';

const Dashboard = () => {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  useEffect(() => {
    const token = localStorage.getItem('accessToken');
    if (!token) {
      navigate('/login');
      return;
    }

    const userData = JSON.parse(localStorage.getItem('user') || '{}');
    setUser(userData);
  }, [navigate]);

  const handleLogout = () => {
    localStorage.clear();
    navigate('/login');
  };

  const handleUploadSuccess = () => {
    setRefreshTrigger((prev) => prev + 1);
  };

  if (!user) {
    return <div>Loading...</div>;
  }

  return (
    <div style={{ minHeight: '100vh', background: '#F9FAFB' }}>
      {/* Header */}
      <header
        style={{
          padding: '20px 30px',
          background: 'white',
          borderBottom: '1px solid #E5E7EB',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}
      >
        <h2 style={{ fontSize: '22px', fontWeight: '600', margin: 0, color: '#111827' }}>
          Secure File Share
        </h2>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          {/* User Info */}
          <div style={{ textAlign: 'right' }}>
            <p style={{ fontSize: '14px', fontWeight: '500', color: '#111827' }}>
              {user.username}
            </p>
            <p style={{ fontSize: '12px', color: '#6B7280' }}>{user.role}</p>
          </div>

          {/* Admin Button */}
          {user.role === 'ADMIN' && (
            <button
              onClick={() => navigate('/admin/dashboard')}
              style={{
                padding: '8px 16px',
                background: '#DC2626',
                color: 'white',
                borderRadius: '6px',
                border: 'none',
                cursor: 'pointer',
                fontWeight: '500'
              }}
            >
              👨‍💼 Admin
            </button>
          )}

          {/* Nav Buttons */}
          <button
            onClick={() => navigate('/shared-files')}
            style={{
              padding: '8px 16px',
              background: '#10B981',
              color: 'white',
              borderRadius: '6px',
              border: 'none',
              cursor: 'pointer',
              fontWeight: '500'
            }}
          >
            👥 Shared Files
          </button>

          <button
            onClick={() => navigate('/settings')}
            style={{
              padding: '8px 16px',
              background: '#6B7280',
              color: 'white',
              borderRadius: '6px',
              border: 'none',
              cursor: 'pointer',
              fontWeight: '500'
            }}
          >
            ⚙️ Settings
          </button>

          <button
            onClick={handleLogout}
            style={{
              padding: '8px 16px',
              background: '#EF4444',
              color: 'white',
              borderRadius: '6px',
              border: 'none',
              cursor: 'pointer',
              fontWeight: '500'
            }}
          >
            Logout
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main style={{ maxWidth: '1400px', margin: '0 auto', padding: '32px' }}>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 2fr',
            gap: '24px'
          }}
        >
          {/* Left Column - File Upload */}
          <div>
            <FileUpload onUploadSuccess={handleUploadSuccess} />
          </div>

          {/* Right Column - File List */}
          <div>
            <FileList refreshTrigger={refreshTrigger} />
          </div>
        </div>

        {/* Security Info Box */}
        <div
          style={{
            marginTop: '32px',
            background: '#DBEAFE',
            border: '1px solid #93C5FD',
            borderRadius: '12px',
            padding: '20px'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'start' }}>
            <span style={{ fontSize: '24px', marginRight: '12px' }}>ℹ️</span>

            <div>
              <h3
                style={{
                  fontSize: '16px',
                  fontWeight: 'bold',
                  color: '#1E40AF',
                  marginBottom: '8px'
                }}
              >
                🔒 Your files are completely secure
              </h3>

              <ul
                style={{
                  fontSize: '14px',
                  color: '#1E3A8A',
                  paddingLeft: '20px',
                  margin: 0,
                  lineHeight: 1.6
                }}
              >
                <li>All files are encrypted with <strong>AES-256</strong> before upload</li>
                <li>Encryption happens in your browser — your password never leaves your device</li>
                <li>File integrity verified with <strong>SHA-256</strong> on every download</li>
                <li>Server stores only encrypted data — zero-knowledge architecture</li>
                <li>Only you can decrypt your files with your password</li>
              </ul>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;