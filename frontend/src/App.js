import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login';
import Register from './components/Register';
import Dashboard from './components/Dashboard';
import Settings from './components/Settings';
import SharedFiles from './components/SharedFiles';
import AdminDashboard from './components/AdminDashboard';
import AuditLogs from './components/AuditLogs';

function App() {
  return (
    <Router>
      <div className="App">
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/shared-files" element={<SharedFiles />} />
          <Route path="/admin/dashboard" element={<AdminDashboard />} />
          <Route path="/admin/audit-logs" element={<AuditLogs />} />
          <Route path="/" element={<Navigate to="/login" />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;