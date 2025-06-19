using microauthd.Config;
using Microsoft.Data.Sqlite;
using SQLitePCL;
namespace microauthd.Data;

public static class DbInitializer
{
    public static void Init(AppConfig config)
    {
        Db.Configure(config);
        Console.WriteLine("Database Initialized.");
    }
    
    public static void CreateDbTables(AppConfig config)
    {
        Db.Configure(config);

        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = GetSchemaSql();
            cmd.ExecuteNonQuery();
        });

        Console.WriteLine("Database Created.");
    }

    private static string GetSchemaSql()
    {
        return """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT,
            created_at TEXT NOT NULL,
            modified_at TEXT,
            last_login TEXT,
            failed_logins INTEGER DEFAULT 0,
            last_failed_login TEXT,
            lockout_until TEXT,
            is_active INTEGER DEFAULT 1,
            email_verified INTEGER DEFAULT 0,
            totp_enabled INTEGER DEFAULT 0,
            totp_secret TEXT
        );
        CREATE TABLE IF NOT EXISTS roles (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            is_protected INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            modified_at TEXT NOT NULL,
            is_active INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS permissions (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            modified_at TEXT,
            is_active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS role_permissions (
            id TEXT PRIMARY KEY,
            role_id TEXT NOT NULL,
            permission_id TEXT NOT NULL,
            assigned_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS user_roles (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            role_id TEXT NOT NULL,
            assigned_at TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS clients (
            id TEXT PRIMARY KEY,
            client_identifier TEXT UNIQUE NOT NULL,
            client_secret_hash TEXT NOT NULL,
            display_name TEXT,
            audience TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            modified_at TEXT NOT NULL DEFAULT (datetime('now')),
            is_active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            client_identifier TEXT,
            token TEXT NOT NULL UNIQUE,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            token_use TEXT DEFAULT 'auth',
            is_revoked INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            client_identifier TEXT,
            refresh_token_hash TEXT NOT NULL UNIQUE,
            refresh_token_sha256 TEXT NOT NULL UNIQUE,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            is_revoked INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS scopes (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            is_protected INTEGER DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            modified_at TEXT NOT NULL DEFAULT (datetime('now')),
            is_active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS user_scopes (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            scope_id TEXT NOT NULL,
            assigned_at TEXT NOT NULL DEFAULT (datetime('now')),
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (scope_id) REFERENCES scopes(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS client_scopes (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            scope_id TEXT NOT NULL,
            assigned_at TEXT NOT NULL DEFAULT (datetime('now')),
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
            FOREIGN KEY (scope_id) REFERENCES scopes(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            action TEXT NOT NULL,
            target TEXT,
            timestamp TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS jti_denylist (
            jti TEXT PRIMARY KEY,
            expires_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
        CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions (token);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);
        CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles (user_id);
        CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles (role_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs (user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs (timestamp);
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens (user_id);
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens (refresh_token_sha256);
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens (expires_at);
        CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name);
        CREATE INDEX IF NOT EXISTS idx_permissions_active ON permissions(is_active);
        CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
        CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);
        CREATE INDEX IF NOT EXISTS idx_role_permissions_active ON role_permissions(is_active);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_role_permission_pair
            ON role_permissions(role_id, permission_id);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_scopes_name ON scopes(name);
        CREATE INDEX IF NOT EXISTS idx_user_scopes_user_id ON user_scopes(user_id);
        CREATE INDEX IF NOT EXISTS idx_user_scopes_scope_id ON user_scopes(scope_id);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_client_id ON clients(client_identifier);
        CREATE INDEX IF NOT EXISTS idx_clients_is_active ON clients(is_active);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_scopes_name ON scopes(name);
        CREATE INDEX IF NOT EXISTS idx_scopes_is_active ON scopes(is_active);
        CREATE INDEX IF NOT EXISTS idx_user_scopes_user_id ON user_scopes(user_id);
        CREATE INDEX IF NOT EXISTS idx_user_scopes_scope_id ON user_scopes(scope_id);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_user_scope_pair_active
          ON user_scopes(user_id, scope_id)
          WHERE is_active = 1;
        CREATE INDEX IF NOT EXISTS idx_client_scopes_client_id ON client_scopes(client_id);
        CREATE INDEX IF NOT EXISTS idx_client_scopes_scope_id ON client_scopes(scope_id);
        CREATE INDEX IF NOT EXISTS idx_jti_expires_at ON jti_denylist(expires_at);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_client_scope_pair_active
          ON client_scopes(client_id, scope_id)
          WHERE is_active = 1;
        CREATE TRIGGER IF NOT EXISTS trg_roles_modified
            AFTER UPDATE ON roles
            FOR EACH ROW
            BEGIN
              UPDATE roles SET modified_at = datetime('now') WHERE id = OLD.id;
        END;
        CREATE TRIGGER IF NOT EXISTS trg_clients_modified
            AFTER UPDATE ON clients
            FOR EACH ROW
            BEGIN
              UPDATE clients SET modified_at = datetime('now') WHERE id = OLD.id;
        END;
        CREATE TRIGGER IF NOT EXISTS trg_scopes_modified
            AFTER UPDATE ON scopes
            FOR EACH ROW
            BEGIN
              UPDATE scopes SET modified_at = datetime('now') WHERE id = OLD.id;
        END;
        INSERT OR IGNORE INTO roles (id, name, description, is_protected, created_at, modified_at, is_active)
            VALUES ('3855db1d-465e-412b-b1f4-b5cd78b4ae9f', 'MadAdmin', 'Administrator role with full access',
            1, datetime('now'), datetime('now'), 1);
        INSERT OR IGNORE INTO scopes (id, name, description, is_protected, created_at, modified_at, is_active)
            VALUES ('d0955db1-67f7-4a7b-a9bb-ffbef4f0d2bd', 'admin:provision_users', 'Provision users scope',
            1, datetime('now'), datetime('now'), 1);
        INSERT OR IGNORE INTO scopes (id, name, description, is_protected, created_at, modified_at, is_active)
            VALUES ('2192998b-c3d3-4274-9a25-4a4195ba2ec7', 'admin:reset_passwords', 'Reset user password scope',
            1, datetime('now'), datetime('now'), 1);
        INSERT OR IGNORE INTO scopes (id, name, description, is_protected, created_at, modified_at, is_active)
            VALUES ('31c00aae-4136-4a8c-92a6-d2bbf4be2d35', 'admin:deactivate_users', 'Deactivate user scope',
            1, datetime('now'), datetime('now'), 1);
        INSERT OR IGNORE INTO scopes (id, name, description, is_protected, created_at, modified_at, is_active)
            VALUES ('1f4610fe-0cb2-4119-bd69-9b6033326998', 'admin:read_user', 'Read user scope',
            1, datetime('now'), datetime('now'), 1);
        INSERT OR IGNORE INTO scopes (id, name, description, is_protected, created_at, modified_at, is_active)
            VALUES ('b6348575-83ec-4288-801b-e0d2da20569c', 'admin:list_users', 'List users scope',
            1, datetime('now'), datetime('now'), 1);
        """;
    }
}
