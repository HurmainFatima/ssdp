-- View all tables
SELECT table_name 
FROM information_schema.tables 
WHERE table_schema = 'public';

-- Count users
SELECT COUNT(*) as total_users FROM accounts_user;

-- View all users
SELECT id, username, email, is_active, date_joined 
FROM accounts_user;

-- View all roles
SELECT * FROM accounts_role;

-- View all files
SELECT id, original_filename, file_size, uploaded_at 
FROM files_encryptedfile 
WHERE is_deleted = false;

-- View all file shares
SELECT fs.id, f.original_filename, 
       u1.username as shared_by, 
       u2.username as shared_with,
       fs.can_download, fs.shared_at
FROM files_fileshare fs
JOIN files_encryptedfile f ON fs.file_id = f.id
JOIN accounts_user u1 ON fs.shared_by_id = u1.id
JOIN accounts_user u2 ON fs.shared_with_id = u2.id;

-- View audit logs (last 20)
SELECT id, action, severity, 
       COALESCE((SELECT username FROM accounts_user WHERE id = user_id), 'Anonymous') as username,
       timestamp, ip_address
FROM audit_auditlog 
ORDER BY timestamp DESC 
LIMIT 20;

-- Count events by action
SELECT action, COUNT(*) as count 
FROM audit_auditlog 
GROUP BY action 
ORDER BY count DESC;

-- Failed login attempts
SELECT user_id, 
       (SELECT username FROM accounts_user WHERE id = audit_auditlog.user_id) as username,
       COUNT(*) as failed_attempts
FROM audit_auditlog 
WHERE action = 'LOGIN_FAILED'
GROUP BY user_id;