using microauthd.Config;
using Microsoft.Data.Sqlite;
using Serilog;
using SQLitePCL;

public static class Db
{
    private static readonly object _lock = new();
    private static SqliteConnection? _sharedConn;
    private static string? _connectionString;
    private static bool _useSqlCipher;
    private static bool _isConfigured = false;

    public static void Configure(AppConfig config)
    {
        if (_isConfigured)
            return;

        Batteries_V2.Init();

        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = config.DbFile,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared
        };

        if (!config.NoDbPass && !string.IsNullOrWhiteSpace(config.DbPass))
        {
            builder.Password = config.DbPass;
            _useSqlCipher = true;
        }
        else
        {
            _useSqlCipher = false;
        }

        _connectionString = builder.ToString();
        _sharedConn = new SqliteConnection(_connectionString);
        _sharedConn.Open();

        VerifySqlCipherIfNeeded(_sharedConn);

        using (var cmd = _sharedConn.CreateCommand())
        {
            cmd.CommandText = """
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA temp_store = MEMORY;
                PRAGMA foreign_keys = ON;
            """;
            cmd.ExecuteNonQuery();
        }

        _isConfigured = true;
    }

    public static void WithConnection(Action<SqliteConnection> action)
    {
        lock (_lock)
        {
            try
            {
                action(_sharedConn ?? throw new InvalidOperationException("DB not initialized"));
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Database access failed.");
                throw;
            }
        }
    }

    public static T WithConnection<T>(Func<SqliteConnection, T> func)
    {
        lock (_lock)
        {
            try
            {
                return func(_sharedConn ?? throw new InvalidOperationException("DB not initialized"));
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Database access failed.");
                throw;
            }
        }
    }

    public static void Vacuum()
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                PRAGMA jounral_mode = DELETE;
                VACUUM;
                PRRAGMA journal_mode = WAL;            
            """;            
            cmd.ExecuteNonQuery();
        });
    }

    public static void FlushWal()
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
            cmd.ExecuteNonQuery();
        });
    }

    private static void VerifySqlCipherIfNeeded(SqliteConnection conn)
    {
        if (_useSqlCipher)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT count(*) FROM sqlite_master;";
            try
            {
                cmd.ExecuteScalar();
            }
            catch (SqliteException ex)
            {
                Log.Fatal(ex, "Failed to verify SQLCipher encryption.");
                throw new InvalidOperationException("Invalid encryption key or corrupted database.", ex);
            }
        }
    }
}
