import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const AuditLogs = () => {
  const navigate = useNavigate();
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  // Filters
  const [actionFilter, setActionFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');

  useEffect(() => {
    checkAdminAccess();
    loadLogs();
  }, []);

  const checkAdminAccess = () => {
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    if (user.role !== 'ADMIN') {
      alert('Admin access required');
      navigate('/dashboard');
    }
  };

  const loadLogs = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('accessToken');
      
      const params = new URLSearchParams();
      if (actionFilter) params.append('action', actionFilter);
      if (severityFilter) params.append('severity', severityFilter);
      if (searchTerm) params.append('search', searchTerm);
      if (startDate) params.append('start_date', startDate);
      if (endDate) params.append('end_date', endDate);
      params.append('limit', '200');
      
      const response = await axios.get(
        `http://localhost:8000/api/audit/logs/?${params.toString()}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      setLogs(response.data.logs || []);
      setError('');
    } catch (err) {
      setError('Failed to load audit logs: ' + (err.response?.data?.error || err.message));
      if (err.response?.status === 403) {
        navigate('/dashboard');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleApplyFilters = () => {
    loadLogs();
  };

  const handleClearFilters = () => {
    setActionFilter('');
    setSeverityFilter('');
    setSearchTerm('');
    setStartDate('');
    setEndDate('');
    setTimeout(() => loadLogs(), 100);
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return { bg: '#FEE2E2', text: '#991B1B', border: '#FCA5A5' };
      case 'HIGH':
        return { bg: '#FED7AA', text: '#9A3412', border: '#FB923C' };
      case 'MEDIUM':
        return { bg: '#FEF3C7', text: '#92400E', border: '#FCD34D' };
      default:
        return { bg: '#E0E7FF', text: '#3730A3', border: '#A5B4FC' };
    }
  };

  if (loading && logs.length === 0) {
    return (
      <div style={{ minHeight: '100vh', background: '#F9FAFB', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '48px', marginBottom: '16px' }}>⏳</div>
          <p style={{ color: '#6B7280' }}>Loading audit logs...</p>
        </div>
      </div>
    );
  }

  return (
    <div style={{ minHeight: '100vh', background: '#F9FAFB' }}>
      {/* Header */}
      <header style={{ background: 'white', boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.1)', padding: '16px 32px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', maxWidth: '1400px', margin: '0 auto' }}>
          <h1 style={{ fontSize: '24px', fontWeight: 'bold', color: '#111827' }}>
            <span style={{ fontSize: '28px', marginRight: '8px' }}>📊</span>
            Audit Logs
          </h1>
          <button
            onClick={() => navigate('/admin/dashboard')}
            style={{
              padding: '8px 16px', background: '#4F46E5', color: 'white',
              borderRadius: '6px', border: 'none', cursor: 'pointer', fontWeight: '500'
            }}
          >
            ← Admin Dashboard
          </button>
        </div>
      </header>

      <main style={{ maxWidth: '1400px', margin: '0 auto', padding: '32px' }}>
        {error && (
          <div style={{ background: '#FEF2F2', border: '1px solid #FEE2E2', color: '#991B1B', padding: '12px', borderRadius: '8px', marginBottom: '16px' }}>
            {error}
          </div>
        )}

        {/* Filters */}
        <div style={{ background: 'white', borderRadius: '12px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', padding: '24px', marginBottom: '24px' }}>
          <h2 style={{ fontSize: '18px', fontWeight: 'bold', marginBottom: '16px' }}>🔍 Filters</h2>

          {/* Filter Inputs */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '16px' }}>
            <div>
              <label style={{ fontSize: '14px', fontWeight: '500', marginBottom: '8px', display: 'block', color: '#374151' }}>
                Action:
              </label>
              <select
                value={actionFilter}
                onChange={(e) => setActionFilter(e.target.value)}
                style={{ width: '100%', padding: '10px', border: '1px solid #D1D5DB', borderRadius: '6px' }}
              >
                <option value="">All Actions</option>
                <option value="LOGIN_SUCCESS">Login Success</option>
                <option value="LOGIN_FAILED">Login Failed</option>
                <option value="FILE_UPLOADED">File Uploaded</option>
                <option value="FILE_DOWNLOADED">File Downloaded</option>
                <option value="FILE_SHARED">File Shared</option>
                <option value="FILE_DELETED">File Deleted</option>
                <option value="SHARE_REVOKED">Share Revoked</option>
                <option value="ROLE_CHANGED">Role Changed</option>
                <option value="MFA_ENABLED">MFA Enabled</option>
                <option value="SECURITY_ALERT">Security Alert</option>
                <option value="UNAUTHORIZED_ACCESS">Unauthorized Access</option>
              </select>
            </div>

            <div>
              <label style={{ fontSize: '14px', fontWeight: '500', marginBottom: '8px', display: 'block', color: '#374151' }}>
                Severity:
              </label>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                style={{ width: '100%', padding: '10px', border: '1px solid #D1D5DB', borderRadius: '6px' }}
              >
                <option value="">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>

            <div>
              <label style={{ fontSize: '14px', fontWeight: '500', marginBottom: '8px', display: 'block', color: '#374151' }}>
                Search:
              </label>
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="User, email, IP..."
                style={{ width: '100%', padding: '10px', border: '1px solid #D1D5DB', borderRadius: '6px' }}
              />
            </div>
          </div>

          {/* Date Filters */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '16px', marginBottom: '16px' }}>
            <div>
              <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500' }}>Start Date:</label>
              <input
                type="datetime-local"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                style={{ width: '100%', padding: '10px', border: '1px solid #D1D5DB', borderRadius: '6px' }}
              />
            </div>

            <div>
              <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500' }}>End Date:</label>
              <input
                type="datetime-local"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                style={{ width: '100%', padding: '10px', border: '1px solid #D1D5DB', borderRadius: '6px' }}
              />
            </div>
          </div>

          {/* Buttons */}
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              onClick={handleApplyFilters}
              disabled={loading}
              style={{
                padding: '10px 20px',
                background: loading ? '#9CA3AF' : '#4F46E5',
                color: 'white',
                borderRadius: '6px',
                cursor: loading ? 'not-allowed' : 'pointer'
              }}
            >
              {loading ? 'Loading...' : 'Apply Filters'}
            </button>

            <button
              onClick={handleClearFilters}
              style={{
                padding: '10px 20px',
                background: '#F3F4F6',
                color: '#374151',
                borderRadius: '6px',
                cursor: 'pointer'
              }}
            >
              Clear Filters
            </button>
          </div>
        </div>

        {/* Logs Section */}
        <div style={{ background: 'white', borderRadius: '12px', padding: '24px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
          
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px' }}>
            <h2 style={{ fontSize: '20px', fontWeight: 'bold' }}>
              Audit Trail ({logs.length} entries)
            </h2>

            <button
              onClick={loadLogs}
              style={{
                padding: '8px 14px',
                background: '#4F46E5',
                color: 'white',
                border: 'none',
                borderRadius: '6px',
                cursor: 'pointer',
                fontWeight: '500'
              }}
            >
              Refresh
            </button>
          </div>

          {logs.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '40px', color: '#6B7280' }}>
              <div style={{ fontSize: '64px', marginBottom: '16px' }}>📋</div>
              <p>No audit logs found matching your criteria.</p>
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {logs.map((log) => {
                  const severityColors = getSeverityColor(log.severity);

                  return (
                    <div
                      key={log.id}
                      style={{
                        border: `1px solid ${severityColors.border}`,
                        borderLeft: `4px solid ${severityColors.border}`,
                        borderRadius: '8px',
                        padding: '16px',
                        background: severityColors.bg + '40'
                      }}
                    >
                      <div>
                        {/* Header Row */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
                          <span
                            style={{
                              padding: '4px 10px',
                              borderRadius: '12px',
                              fontSize: '12px',
                              fontWeight: '600',
                              background: severityColors.bg,
                              color: severityColors.text,
                              border: `1px solid ${severityColors.border}`
                            }}
                          >
                            {log.severity_display}
                          </span>

                          <span style={{ fontSize: '16px', fontWeight: '600', color: '#111827' }}>
                            {log.action_display}
                          </span>
                        </div>

                        {/* Meta Row */}
                        <div style={{ display: 'flex', gap: '20px', fontSize: '14px', color: '#6B7280', flexWrap: 'wrap' }}>
                          <span>👤 <strong>{log.user || 'Anonymous'}</strong></span>
                          {log.user_email && <span>📧 {log.user_email}</span>}
                          {log.ip_address && <span>🌐 {log.ip_address}</span>}
                          <span>🕐 {new Date(log.timestamp).toLocaleString()}</span>
                        </div>

                        {/* Details */}
                        {log.details && Object.keys(log.details).length > 0 && (
                          <div style={{ marginTop: '12px', padding: '12px', background: 'white', borderRadius: '6px' }}>
                            <strong>Details:</strong>
                            <pre style={{ marginTop: '8px', fontSize: '13px', whiteSpace: 'pre-wrap' }}>
                              {JSON.stringify(log.details, null, 2)}
                            </pre>
                          </div>
                        )}

                        {/* User Agent */}
                        {log.user_agent && (
                          <div style={{ marginTop: '8px', fontSize: '12px', color: '#9CA3AF', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            🖥️ {log.user_agent}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default AuditLogs;
