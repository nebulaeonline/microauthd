using System;
using System.Collections.Generic;
using System.Data;
using madTypes.Api.Common;

namespace microauthd.Data;

public static class AuthSessionStore
{
    /// <summary>
    /// Inserts a new authentication session record into the database.
    /// </summary>
    /// <remarks>The <paramref name="session"/> object provides details about the authentication session,
    /// including identifiers, client information, user information, and expiration details. All required fields in the
    /// session object must be populated before calling this method.  Nullable fields in the session object, such as
    /// <c>UserId</c>, <c>Nonce</c>, <c>Scope</c>, and <c>State</c>, will be stored as <see cref="DBNull.Value"/> if
    /// they are <see langword="null"/>.</remarks>
    /// <param name="session">The authentication session data to insert. This parameter must not be <see langword="null"/>.</param>
    public static void Insert(AuthSessionDto session)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO auth_sessions (jti, client_id, user_id, redirect_uri, totp_required, nonce, scope, state, code_challenge, code_challenge_method, created_at, expires_at, login_method)
                VALUES ($jti, $client_id, $user_id, $redirect_uri, $totp_required, $nonce, $scope, $state, $code_challenge, $code_challenge_method, $created, $expires, $login_method);
            """;
            cmd.Parameters.AddWithValue("$jti", session.Jti);
            cmd.Parameters.AddWithValue("$client_id", session.ClientId);
            cmd.Parameters.AddWithValue("$user_id", (object?)session.UserId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$redirect_uri", session.RedirectUri);
            cmd.Parameters.AddWithValue("$totp_required", session.TotpRequired);
            cmd.Parameters.AddWithValue("$nonce", (object?)session.Nonce ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$scope", (object?)session.Scope ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$state", (object?)session.State ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$code_challenge", session.CodeChallenge);
            cmd.Parameters.AddWithValue("$code_challenge_method", session.CodeChallengeMethod);
            cmd.Parameters.AddWithValue("$created", session.CreatedAtUtc);
            cmd.Parameters.AddWithValue("$expires", session.ExpiresAtUtc);
            cmd.Parameters.AddWithValue("$login_method", (object?)session.LoginMethod ?? DBNull.Value);
            cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// Retrieves an authentication session based on the specified JSON Web Token identifier (JTI).
    /// </summary>
    /// <remarks>This method queries the database for an authentication session matching the provided JTI. If
    /// no matching session is found, the method returns <see langword="null"/>. The returned <see
    /// cref="AuthSessionDto"/> contains details such as client ID, user ID, redirect URI, and other session-related
    /// information.</remarks>
    /// <param name="jti">The unique identifier of the JSON Web Token (JTI) associated with the authentication session. Cannot be null or
    /// empty.</param>
    /// <returns>An <see cref="AuthSessionDto"/> object representing the authentication session if found; otherwise, <see
    /// langword="null"/>.</returns>
    public static AuthSessionDto? Get(string jti)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT jti, client_id, user_id, redirect_uri, totp_required, nonce, scope, state, code_challenge, code_challenge_method, created_at, expires_at, login_method
                FROM auth_sessions
                WHERE jti = $jti;
            """;
            cmd.Parameters.AddWithValue("$jti", jti);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read()) return null;

            return new AuthSessionDto
            {
                Jti = jti,
                ClientId = reader.GetString(1),
                UserId = reader.IsDBNull(2) ? null : reader.GetString(2),
                RedirectUri = reader.GetString(3),
                TotpRequired = reader.GetBoolean(4),
                Nonce = reader.IsDBNull(5) ? null : reader.GetString(5),
                Scope = reader.IsDBNull(6) ? null : reader.GetString(6),
                State = reader.IsDBNull(7) ? null : reader.GetString(7),
                CodeChallenge = reader.GetString(8),
                CodeChallengeMethod = reader.GetString(9),
                CreatedAtUtc = reader.GetDateTime(10).ToUniversalTime(),
                ExpiresAtUtc = reader.GetDateTime(11).ToUniversalTime(),
                LoginMethod = reader.IsDBNull(12) ? null : reader.GetString(12)
            };
        });
    }

    /// <summary>
    /// Associates a login method with an authentication session identified by the specified token.
    /// </summary>
    /// <remarks>This method updates the login method for an existing authentication session in the database.
    /// Ensure that the <paramref name="jti"/> corresponds to a valid session before calling this method.</remarks>
    /// <param name="jti">The unique identifier of the authentication session. This value cannot be null or empty.</param>
    /// <param name="loginMethod">The login method to associate with the authentication session. This value cannot be null or empty.</param>
    public static void AttachLoginMethod(string jti, string loginMethod)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE auth_sessions
                SET login_method = $login_method
                WHERE jti = $jti;
            """;
            cmd.Parameters.AddWithValue("$jti", jti);
            cmd.Parameters.AddWithValue("$login_method", loginMethod);
            cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// Associates a user ID and a flag indicating whether TOTP is required with an authentication session.
    /// </summary>
    /// <remarks>This method updates the authentication session identified by <paramref name="jti"/> in the
    /// database, setting the associated user ID and the TOTP requirement flag. Ensure that the provided <paramref
    /// name="jti"/> corresponds to a valid session in the database.</remarks>
    /// <param name="jti">The unique identifier of the authentication session. Cannot be null or empty.</param>
    /// <param name="userId">The user ID to associate with the session. Cannot be null or empty.</param>
    /// <param name="totpRequired">A value indicating whether TOTP is required for the session. <see langword="true"/> if TOTP is required;
    /// otherwise, <see langword="false"/>.</param>
    public static void AttachUserIdAndTotpFlag(string jti, string userId, bool totpRequired)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE auth_sessions
                SET user_id = $userId,
                    totp_required = $totp
                WHERE jti = $jti;
            """;
            cmd.Parameters.AddWithValue("$userId", userId);
            cmd.Parameters.AddWithValue("$totp", totpRequired ? 1 : 0);
            cmd.Parameters.AddWithValue("$jti", jti);
            cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// Retrieves and deletes an authentication session from the database based on the specified unique identifier
    /// (JTI).
    /// </summary>
    /// <remarks>This method performs the following operations: <list type="bullet">
    /// <item><description>Retrieves the authentication session associated with the specified JTI.</description></item>
    /// <item><description>Deletes the session from the database after retrieval.</description></item> </list> The
    /// method ensures that the session is consumed atomically by using a database transaction.</remarks>
    /// <param name="jti">The unique identifier of the authentication session to consume. This value must not be null or empty.</param>
    /// <returns>An <see cref="AuthSessionDto"/> object containing the details of the consumed authentication session,  or <see
    /// langword="null"/> if no session with the specified JTI exists.</returns>
    public static AuthSessionDto? Consume(string jti)
    {
        return Db.WithConnection(conn =>
        {
            using var tx = conn.BeginTransaction();
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                SELECT jti, client_id, user_id, redirect_uri, totp_required, nonce, scope, state, code_challenge, code_challenge_method, created_at, expires_at, login_method
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
                ClientId = reader.GetString(1),
                UserId = reader.IsDBNull(2) ? null : reader.GetString(2),
                RedirectUri = reader.GetString(3),
                TotpRequired = reader.GetBoolean(4),
                Nonce = reader.IsDBNull(5) ? null : reader.GetString(5),
                Scope = reader.IsDBNull(6) ? null : reader.GetString(6),
                State = reader.IsDBNull(7) ? null : reader.GetString(7),
                CodeChallenge = reader.GetString(8),
                CodeChallengeMethod = reader.GetString(9),
                CreatedAtUtc = reader.GetDateTime(10).ToUniversalTime(),
                ExpiresAtUtc = reader.GetDateTime(11).ToUniversalTime(),
                LoginMethod = reader.IsDBNull(12) ? null : reader.GetString(12)
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

    /// <summary>
    /// Removes expired authentication sessions from the database.
    /// </summary>
    /// <remarks>This method deletes all records from the <c>auth_sessions</c> table where the expiration
    /// timestamp has passed. It is intended to be used for periodic cleanup of expired sessions.</remarks>
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
