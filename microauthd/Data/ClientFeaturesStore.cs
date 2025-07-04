using microauthd.Common;

namespace microauthd.Data;

public static class ClientFeaturesStore
{
    public static void SetClientFeatureFlag(string clientId, ClientFeatures.Flags featureFlag, bool isEnabled, string options = "")
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO client_features (id, client_id, feature_flag, is_enabled, options)
                VALUES ($id, $client_id, $feature_flag, $is_enabled, $options)
                ON CONFLICT(client_id, feature_flag) DO UPDATE SET
                    is_enabled = excluded.is_enabled,
                    options = excluded.options;
            """;
            cmd.Parameters.AddWithValue("$id", Guid.NewGuid().ToString());
            cmd.Parameters.AddWithValue("$client_id", clientId);
            cmd.Parameters.AddWithValue("$feature_flag", ClientFeatures.GetFlagString(featureFlag));
            cmd.Parameters.AddWithValue("$is_enabled", isEnabled ? 1 : 0);
            cmd.Parameters.AddWithValue("$options", options);
            cmd.ExecuteNonQuery();
        });
    }

    public static bool? IsFeatureEnabled(string clientId, ClientFeatures.Flags featureFlag)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT is_enabled FROM client_features
                WHERE client_id = $client_id AND feature_flag = $feature_flag;
            """;
            cmd.Parameters.AddWithValue("$client_id", clientId);
            cmd.Parameters.AddWithValue("$feature_flag", ClientFeatures.GetFlagString(featureFlag));

            using var reader = cmd.ExecuteReader();
            if (!reader.Read()) return (bool?)null; // feature is unset
            return reader.GetBoolean(0);
        });
    }

    public static string? GetFeatureOption(string clientId, ClientFeatures.Flags featureFlag)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT options FROM client_features
                WHERE client_id = $client_id AND feature_flag = $feature_flag;
            """;
            cmd.Parameters.AddWithValue("$client_id", clientId);
            cmd.Parameters.AddWithValue("$feature_flag", ClientFeatures.GetFlagString(featureFlag));

            using var reader = cmd.ExecuteReader();
            return reader.Read() ? reader.GetString(0) : null;
        });
    }

    public static void SetFeatureOption(string clientId, ClientFeatures.Flags featureFlag, string options)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE client_features
                SET options = $options
                WHERE client_id = $client_id AND feature_flag = $feature_flag;
            """;
            cmd.Parameters.AddWithValue("$options", options);
            cmd.Parameters.AddWithValue("$client_id", clientId);
            cmd.Parameters.AddWithValue("$feature_flag", ClientFeatures.GetFlagString(featureFlag));
            cmd.ExecuteNonQuery();
        });
    }
}
