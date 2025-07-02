using System;
using System.Collections.Generic;
using System.Data;
using madTypes.Api.Common;

namespace microauthd.Data;

public static class AuthSessionStore
{
    public static void Insert(AuthSessionDto session)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO auth_sessions (jti, query_string, created_at, expires_at)
                VALUES ($jti, $qs, $created, $expires);
            """;
            cmd.Parameters.AddWithValue("$jti", session.Jti);
            cmd.Parameters.AddWithValue("$qs", session.QueryString);
            cmd.Parameters.AddWithValue("$created", session.CreatedAtUtc);
            cmd.Parameters.AddWithValue("$expires", session.ExpiresAtUtc);
            cmd.ExecuteNonQuery();
        });
    }

    public static AuthSessionDto? Get(string jti)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
            SELECT query_string, created_at, expires_at
            FROM auth_sessions
            WHERE jti = $jti;
        """;
            cmd.Parameters.AddWithValue("$jti", jti);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read()) return null;

            return new AuthSessionDto
            {
                Jti = jti,
                QueryString = reader.GetString(0),
                CreatedAtUtc = reader.GetDateTime(1).ToUniversalTime(),
                ExpiresAtUtc = reader.GetDateTime(2).ToUniversalTime()
            };
        });
    }

    public static AuthSessionDto? Consume(string jti)
    {
        return Db.WithConnection(conn =>
        {
            using var tx = conn.BeginTransaction();
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                SELECT query_string, created_at, expires_at
                FROM auth_sessions
                WHERE jti = $jti;
            """;
            cmd.Parameters.AddWithValue("$jti", jti);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
            {
                tx.Rollback();
                return null;
            }

            var dto = new AuthSessionDto
            {
                Jti = jti,
                QueryString = reader.GetString(0),
                CreatedAtUtc = reader.GetDateTime(1).ToUniversalTime(),
                ExpiresAtUtc = reader.GetDateTime(2).ToUniversalTime()
            };

            reader.Close();

            using var delCmd = conn.CreateCommand();
            delCmd.Transaction = tx;
            delCmd.CommandText = "DELETE FROM auth_sessions WHERE jti = $jti;";
            delCmd.Parameters.AddWithValue("$jti", jti);
            delCmd.ExecuteNonQuery();

            tx.Commit();
            return dto;
        });
    }

    public static void PurgeExpired()
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                DELETE FROM auth_sessions
                WHERE expires_at <= CURRENT_TIMESTAMP;
            """;
            cmd.ExecuteNonQuery();
        });
    }
}
