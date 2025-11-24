import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/client';

const AdminDashboard = () => {
  const navigate = useNavigate();
  const [users, setUsers] = useState([]);
  const [auditStats, setAuditStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedUser, setSelectedUser] = useState(null);
  const [showRoleModal, setShowRoleModal] = useState(false);
  const [newRole, setNewRole] = useState('');

  useEffect(() => {
    checkAdminAccess();
    loadData();
  }, []);

  const checkAdminAccess = () => {
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    if (user.role !== 'ADMIN') {
      alert('Admin access required');
      navigate('/dashboard');
    }
  };

  const loadData = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('accessToken');

      const [usersResponse, statsResponse] = await Promise.all([
        api.get('auth/admin/users/', { headers: { Authorization: `Bearer ${token}` } }),
        api.get('audit/stats/', { headers: { Authorization: `Bearer ${token}` } }),
      ]);

      setUsers(usersResponse.data.users || []);
      setAuditStats(statsResponse.data || {});
      setError('');
    } catch (err) {
      console.error('Admin data load error:', err);
      setError('Failed to load admin data: ' + (err.response?.data?.error || err.message));
      if (err.response?.status === 403) {
        navigate('/dashboard');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleChangeRole = async () => {
    if (!newRole) {
      alert('Please select a role');
      return;
    }

    try {
      const token = localStorage.getItem('accessToken');
      await api.post(
        `auth/admin/users/${selectedUser.id}/role/`,
        { role: newRole },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      alert('✅ User role updated successfully');
      setShowRoleModal(false);
      setSelectedUser(null);
      setNewRole('');
      loadData();
    } catch (err) {
      console.error('Role update error:', err);
      alert('Failed to update role: ' + (err.response?.data?.error || err.message));
    }
  };

  const handleToggleStatus = async (user) => {
    const action = user.is_active ? 'disable' : 'enable';
    if (!window.confirm(`Are you sure you want to ${action} ${user.username}?`)) {
      return;
    }

    try {
      const token = localStorage.getItem('accessToken');
      await api.post(
        `auth/admin/users/${user.id}/toggle/`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );

      alert(`✅ User ${action}d successfully`);
      loadData();
    } catch (err) {
      console.error('Toggle status error:', err);
      alert(`Failed to ${action} user: ` + (err.response?.data?.error || err.message));
    }
  };

  const openRoleModal = (user) => {
    setSelectedUser(user);
    setNewRole(user.role);
    setShowRoleModal(true);
  };

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', background: '#F9FAFB', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '48px', marginBottom: '16px' }}>⏳</div>
          <p style={{ color: '#6B7280' }}>Loading admin dashboard...</p>
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
            <span style={{ fontSize: '28px', marginRight: '8px' }}>👨‍💼</span>
            Admin Dashboard
          </h1>
          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              onClick={() => navigate('/admin/audit-logs')}
              style={{ padding: '8px 16px', background: '#6B7280', color: 'white', borderRadius: '6px', border: 'none', cursor: 'pointer', fontWeight: '500' }}
            >
              📊 Audit Logs
            </button>
            <button
              onClick={() => navigate('/dashboard')}
              style={{ padding: '8px 16px', background: '#4F46E5', color: 'white', borderRadius: '6px', border: 'none', cursor: 'pointer', fontWeight: '500' }}
            >
              ← Dashboard
            </button>
          </div>
        </div>
      </header>

      <main style={{ maxWidth: '1400px', margin: '0 auto', padding: '32px' }}>
        {error && (
          <div style={{ background: '#FEF2F2', border: '1px solid #FEE2E2', color: '#991B1B', padding: '12px', borderRadius: '8px', marginBottom: '16px' }}>
            {error}
          </div>
        )}

        {/* Statistics Cards */}
        {auditStats && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '32px' }}>
            <StatCard
              title="Total Users"
              value={users.length}
              icon="👥"
              color="#3B82F6"
            />
            <StatCard
              title="Login Success (7d)"
              value={auditStats.login_success}
              icon="✅"
              color="#10B981"
            />
            <StatCard
              title="Failed Logins (7d)"
              value={auditStats.login_failed}
              icon="❌"
              color="#EF4444"
            />
            <StatCard
              title="Security Alerts"
              value={auditStats.critical_alerts + auditStats.high_alerts}
              icon="⚠️"
              color="#F59E0B"
            />
          </div>
        )}

        {/* Recent Security Alerts */}
        {auditStats && auditStats.recent_alerts.length > 0 && (
          <div style={{ background: 'white', borderRadius: '12px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', padding: '24px', marginBottom: '32px' }}>
            <h2 style={{ fontSize: '18px', fontWeight: 'bold', marginBottom: '16px', color: '#DC2626' }}>
              ⚠️ Recent Security Alerts
            </h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {auditStats.recent_alerts.slice(0, 5).map((alert) => (
                <div
                  key={alert.id}
                  style={{ 
                    padding: '12px', 
                    background: '#FEF2F2', 
                    border: '1px solid #FEE2E2', 
                    borderRadius: '6px',
                    fontSize: '14px'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <strong>{alert.action_display}</strong> - {alert.user || 'Anonymous'}
                      {alert.ip_address && <span style={{ color: '#6B7280', marginLeft: '8px' }}>({alert.ip_address})</span>}
                    </div>
                    <span style={{ fontSize: '12px', color: '#6B7280' }}>
                      {new Date(alert.timestamp).toLocaleString()}
                    </span>
                  </div>
                  {alert.details && Object.keys(alert.details).length > 0 && (
                    <div style={{ fontSize: '12px', color: '#6B7280', marginTop: '4px' }}>
                      {JSON.stringify(alert.details)}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Users Table */}
        <div style={{ background: 'white', borderRadius: '12px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', padding: '24px' }}>
          <h2 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '20px' }}>
            👥 User Management
          </h2>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid #E5E7EB' }}>
                  <th style={{ padding: '12px', textAlign: 'left', fontSize: '14px', fontWeight: '600', color: '#374151' }}>User</th>
                  <th style={{ padding: '12px', textAlign: 'left', fontSize: '14px', fontWeight: '600', color: '#374151' }}>Role</th>
                  <th style={{ padding: '12px', textAlign: 'left', fontSize: '14px', fontWeight: '600', color: '#374151' }}>Status</th>
                  <th style={{ padding: '12px', textAlign: 'left', fontSize: '14px', fontWeight: '600', color: '#374151' }}>MFA</th>
                  <th style={{ padding: '12px', textAlign: 'left', fontSize: '14px', fontWeight: '600', color: '#374151' }}>Joined</th>
                  <th style={{ padding: '12px', textAlign: 'left', fontSize: '14px', fontWeight: '600', color: '#374151' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user.id} style={{ borderBottom: '1px solid #E5E7EB' }}>
                    <td style={{ padding: '12px' }}>
                      <div>
                        <div style={{ fontWeight: '500', color: '#111827' }}>{user.username}</div>
                        <div style={{ fontSize: '13px', color: '#6B7280' }}>{user.email}</div>
                      </div>
                    </td>
                    <td style={{ padding: '12px' }}>
                      <span style={{ 
                        padding: '4px 12px', 
                        borderRadius: '12px', 
                        fontSize: '12px', 
                        fontWeight: '500',
                        background: user.role === 'ADMIN' ? '#DBEAFE' : user.role === 'USER' ? '#D1FAE5' : '#FEF3C7',
                        color: user.role === 'ADMIN' ? '#1E40AF' : user.role === 'USER' ? '#065F46' : '#92400E'
                      }}>
                        {user.role}
                      </span>
                    </td>
                    <td style={{ padding: '12px' }}>
                      <span style={{ 
                        padding: '4px 12px', 
                        borderRadius: '12px', 
                        fontSize: '12px', 
                        fontWeight: '500',
                        background: user.is_active ? '#D1FAE5' : '#FEE2E2',
                        color: user.is_active ? '#065F46' : '#991B1B'
                      }}>
                        {user.is_active ? 'Active' : 'Disabled'}
                      </span>
                    </td>
                    <td style={{ padding: '12px' }}>
                      <span style={{ fontSize: '14px' }}>
                        {user.mfa_enabled ? '✅' : '❌'}
                      </span>
                    </td>
                    <td style={{ padding: '12px', fontSize: '13px', color: '#6B7280' }}>
                      {new Date(user.date_joined).toLocaleDateString()}
                    </td>
                    <td style={{ padding: '12px' }}>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <button
                          onClick={() => openRoleModal(user)}
                          style={{ 
                            padding: '6px 12px', 
                            background: '#4F46E5', 
                            color: 'white', 
                            border: 'none', 
                            borderRadius: '6px', 
                            cursor: 'pointer',
                            fontSize: '12px',
                            fontWeight: '500'
                          }}
                        >
                          Change Role
                        </button>
                        <button
                          onClick={() => handleToggleStatus(user)}
                          style={{ 
                            padding: '6px 12px', 
                            background: user.is_active ? '#EF4444' : '#10B981', 
                            color: 'white', 
                            border: 'none', 
                            borderRadius: '6px', 
                            cursor: 'pointer',
                            fontSize: '12px',
                            fontWeight: '500'
                          }}
                        >
                          {user.is_active ? 'Disable' : 'Enable'}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Change Role Modal */}
        {showRoleModal && (
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
                Change User Role
              </h3>
              <p style={{ fontSize: '14px', color: '#6B7280', marginBottom: '16px' }}>
                Change role for: <strong>{selectedUser?.username}</strong>
              </p>
              
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: '500', marginBottom: '8px' }}>
                  Select Role:
                </label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value)}
                  style={{ 
                    width: '100%', 
                    padding: '12px', 
                    border: '1px solid #D1D5DB', 
                    borderRadius: '8px',
                    fontSize: '14px'
                  }}
                >
                  <option value="ADMIN">Admin</option>
                  <option value="USER">User</option>
                  <option value="VIEWER">Viewer</option>
                </select>
              </div>

              <div style={{ background: '#FEF3C7', border: '1px solid #FCD34D', borderRadius: '8px', padding: '12px', marginBottom: '16px' }}>
                <p style={{ fontSize: '13px', color: '#92400E', margin: 0 }}>
                  <strong>Admin:</strong> Full access including user management<br/>
                  <strong>User:</strong> Can upload, download, and share files<br/>
                  <strong>Viewer:</strong> Can only view and download files
                </p>
              </div>

              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  onClick={() => {
                    setShowRoleModal(false);
                    setSelectedUser(null);
                    setNewRole('');
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
                  onClick={handleChangeRole}
                  disabled={!newRole}
                  style={{ 
                    flex: 1,
                    padding: '12px', 
                    background: newRole ? '#4F46E5' : '#9CA3AF', 
                    color: 'white', 
                    border: 'none', 
                    borderRadius: '8px', 
                    cursor: newRole ? 'pointer' : 'not-allowed',
                    fontWeight: '500'
                  }}
                >
                  Update Role
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

const StatCard = ({ title, value, icon, color }) => {
  return (
    <div style={{ background: 'white', borderRadius: '12px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', padding: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '12px' }}>
        <div style={{ fontSize: '32px' }}>{icon}</div>
        <div style={{ 
          padding: '6px 12px', 
          borderRadius: '6px', 
          background: color + '20',
          color: color,
          fontSize: '24px',
          fontWeight: 'bold'
        }}>
          {value}
        </div>
      </div>
      <div style={{ fontSize: '14px', fontWeight: '500', color: '#6B7280' }}>
        {title}
      </div>
    </div>
  );
};

export default AdminDashboard;
