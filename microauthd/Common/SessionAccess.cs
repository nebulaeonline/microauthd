namespace microauthd.Common;

public static class SessionAccess
{
    public static bool IsSessionActive(string userId, string jti)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT COUNT(*) FROM sessions
                WHERE user_id = $uid AND id = $jti AND is_revoked = 0;
            """;
            cmd.Parameters.AddWithValue("$uid", userId);
            cmd.Parameters.AddWithValue("$jti", jti);

            var count = Convert.ToInt32(cmd.ExecuteScalar());
            return count > 0;
        });
    }
}
