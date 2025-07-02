using Serilog;
using System;
using System.Data;

namespace microauthd.Data;

public static class DbMigrations
{
    // Schema versioning
    private const int CurrentSchemaVersion = 7;

    /// <summary>
    /// Applies all necessary database schema migrations to bring the database up to the current schema version.
    /// </summary>
    /// <remarks>This method checks the current schema version of the database and applies incremental
    /// migrations until the database matches the expected schema version defined by the application. If the database
    /// schema version is newer than the version supported by the application, an exception is thrown.</remarks>
    /// <exception cref="InvalidOperationException">Thrown if the database schema version is newer than the version supported by the application.</exception>
    public static void ApplyMigrations()
    {
        // Get the current schema version for the database
        int dbVersion = GetSchemaVersion();

        // If db is too new, don't run any migrations
        if (dbVersion > CurrentSchemaVersion)
            throw new InvalidOperationException($"Database schema version ({dbVersion}) is newer than this binary supports ({CurrentSchemaVersion}).");

        // Apply migrations until we reach the current schema version
        while (dbVersion < CurrentSchemaVersion)
        {
            int nextVersion = dbVersion + 1;
            Log.Information("Migrating schema: v{From} to v{To}", dbVersion, nextVersion);
            ApplyMigrationStep(dbVersion, nextVersion);
            SetSchemaVersion(nextVersion);
            dbVersion = nextVersion;
        }

        Log.Information("Database schema is up to date (v{Version})", dbVersion);
    }

    /// <summary>
    /// Retrieves the current schema version from the database.
    /// </summary>
    /// <remarks>This method queries the `schema_version` table in the database to obtain the schema version. 
    /// If the table does not exist, it is created with an initial version of 1, and the method returns 1.</remarks>
    /// <returns>The current schema version as an integer. Returns 1 if the `schema_version` table is missing and is created.</returns>
    private static int GetSchemaVersion()
    {
        try
        {
            return Db.WithConnection(conn =>
            {
                using var checkCmd = conn.CreateCommand();
                checkCmd.CommandText = "SELECT version FROM schema_version WHERE id = 1;";
                return Convert.ToInt32(checkCmd.ExecuteScalar());
            });
        }
        catch
        {
            // schema_version table missing; create it and assume version 1
            Db.WithConnection(conn =>
            {
                using var create = conn.CreateCommand();
                create.CommandText = """
                    CREATE TABLE IF NOT EXISTS schema_version (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        version INTEGER NOT NULL
                    );
                    INSERT OR IGNORE INTO schema_version (id, version) VALUES (1, 1);
                """;
                create.ExecuteNonQuery();
            });
            return 1;
        }
    }

    /// <summary>
    /// Updates the schema version in the database to the specified value.
    /// </summary>
    /// <remarks>This method updates the schema version in the database by executing an SQL command. Ensure
    /// that the database connection is properly configured before calling this method.</remarks>
    /// <param name="version">The new schema version to set. Must be a positive integer.</param>
    private static void SetSchemaVersion(int version)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE schema_version SET version = $v WHERE id = 1;";
            cmd.Parameters.AddWithValue("$v", version);
            cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// Determines whether a specified column exists in a given table within the database.
    /// </summary>
    /// <remarks>This method queries the database schema to determine the existence of the column. It uses the
    /// SQLite PRAGMA table_info command to retrieve metadata about the specified table.</remarks>
    /// <param name="tableName">The name of the table to check. Cannot be null or empty.</param>
    /// <param name="columnName">The name of the column to check for existence. Cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the specified column exists in the table; otherwise, <see langword="false"/>.</returns>
    private static bool ColumnExists(string tableName, string columnName)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = $"PRAGMA table_info({tableName});";

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                if (reader["name"]?.ToString() == columnName)
                    return true;
            }

            return false;
        });
    }

    /// <summary>
    /// Applies a migration step to transition the system from one version to another.
    /// </summary>
    /// <remarks>This method performs the necessary operations to migrate the system state from the specified 
    /// <paramref name="fromVersion"/> to <paramref name="toVersion"/>. If no migration is defined for  the specified
    /// version pair, an exception is thrown.</remarks>
    /// <param name="fromVersion">The current version of the system. Must be a valid version number.</param>
    /// <param name="toVersion">The target version to migrate to. Must be a valid version number.</param>
    /// <exception cref="InvalidOperationException">Thrown if no migration is defined for the specified <paramref name="fromVersion"/> and <paramref
    /// name="toVersion"/>.</exception>
    private static void ApplyMigrationStep(int fromVersion, int toVersion)
    {
        switch ((fromVersion, toVersion))
        {
            case (1, 2):
                Migrate_1_to_2();
                break;
            case (2, 3):
                Migrate_2_to_3();
                break;
            case (3, 4):
                Migrate_3_to_4();
                break;
            case (4, 5):
                Migrate_4_to_5();
                break;
            case (5, 6):
                Migrate_5_to_6();
                break;
            case (6, 7):
                Migrate_6_to_7();
                break;
            default:
                throw new InvalidOperationException($"No migration defined for v{fromVersion} → v{toVersion}");
        }
    }

    // Migration: v1 to v2
    // Add `nonce` column to `pkce_codes` table
    private static void Migrate_1_to_2()
    {
        if (!ColumnExists("pkce_codes", "nonce"))
        {
            Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "ALTER TABLE pkce_codes ADD COLUMN nonce TEXT DEFAULT '';";
                cmd.ExecuteNonQuery();
            });
        }
    }

    // Migration: v2 to v3
    // Add nonce tracking table
    private static void Migrate_2_to_3()
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE IF NOT EXISTS oidc_nonces (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_nonce_lookup
                    ON oidc_nonces (client_id, user_id, nonce);
                CREATE INDEX IF NOT EXISTS idx_nonce_created
                    ON oidc_nonces (created_at);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_nonce_user_client 
                    ON oidc_nonces(user_id, client_id, nonce);
            """;
            cmd.ExecuteNonQuery();
        });
    }

    // Migration: v3 to v4
    // Add `mad_use` column to `sessions` table
    private static void Migrate_3_to_4()
    {
        if (!ColumnExists("sessions", "mad_use"))
        {
            Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "ALTER TABLE sessions ADD COLUMN mad_use TEXT DEFAULT '';";
                cmd.ExecuteNonQuery();
            });
        }
    }

    // Migration: v4 to v5
    // Add AuthSession table
    private static void Migrate_4_to_5()
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    jti TEXT PRIMARY KEY,
                    query_string TEXT NOT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_auth_session_expiration 
                    ON auth_sessions (expires_at);
            """;
            cmd.ExecuteNonQuery();
        });
    }

    // Migration: v5 to v6
    // Add `scope` column to `pkce_codes` table
    private static void Migrate_5_to_6()
    {
        if (!ColumnExists("pkce_codes", "scope"))
        {
            Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "ALTER TABLE pkce_codes ADD COLUMN scope TEXT;";
                cmd.ExecuteNonQuery();
            });
        }
    }

    // Migration: v6 to v7
    // Add `is_openid_token` column to `refresh_tokens` table
    private static void Migrate_6_to_7()
    {
        if (!ColumnExists("refresh_tokens", "is_openid_token"))
        {
            Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "ALTER TABLE refresh_tokens ADD COLUMN is_openid_token INT DEFAULT 0;";
                cmd.ExecuteNonQuery();
            });
        }
    }
}
