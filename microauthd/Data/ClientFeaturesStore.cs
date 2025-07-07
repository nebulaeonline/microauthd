using madTypes.Common;

namespace microauthd.Data;

public static class ClientFeaturesStore
{
    /// <summary>
    /// Sets the specified feature flag for a client, enabling or disabling it as specified.
    /// </summary>
    /// <remarks>If the feature flag already exists for the specified client, its state and options will be
    /// updated. Otherwise, a new entry will be created.</remarks>
    /// <param name="clientId">The unique identifier of the client for which the feature flag is being set.</param>
    /// <param name="featureFlag">The feature flag to be set. This must be a valid flag defined in <see cref="ClientFeatures.Flags"/>.</param>
    /// <param name="isEnabled"><see langword="true"/> to enable the feature flag; otherwise, <see langword="false"/> to disable it.</param>
    /// <param name="options">Optional configuration settings for the feature flag. If not specified, defaults to an empty string.</param>
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

    /// <summary>
    /// Determines whether a specific feature is enabled for a given client.
    /// </summary>
    /// <remarks>This method queries the database to determine the feature's state for the specified client.
    /// The result is based on the value stored in the database, which can be one of three states: enabled, disabled, or
    /// unset.</remarks>
    /// <param name="clientId">The unique identifier of the client. Cannot be null or empty.</param>
    /// <param name="featureFlag">The feature flag to check. Represents the specific feature being queried.</param>
    /// <returns><see langword="true"/> if the feature is enabled for the client;  <see langword="false"/> if the feature is
    /// explicitly disabled;  <see langword="null"/> if the feature is not set for the client.</returns>
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

    /// <summary>
    /// Retrieves the feature option associated with a specific client and feature flag.
    /// </summary>
    /// <remarks>This method queries the database to retrieve the feature option for the specified client and
    /// feature flag. If no matching record is found, the method returns <see langword="null"/>.</remarks>
    /// <param name="clientId">The unique identifier of the client. This value cannot be <see langword="null"/> or empty.</param>
    /// <param name="featureFlag">The feature flag for which the option is being retrieved.</param>
    /// <returns>A string representing the feature option if found; otherwise, <see langword="null"/>.</returns>
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

    /// <summary>
    /// Retrieves the integer value of a feature option for a specified client.
    /// </summary>
    /// <remarks>This method attempts to parse the feature option value as an integer. If the feature option
    /// is not defined  or cannot be parsed as an integer, the method returns <see langword="null"/>.</remarks>
    /// <param name="clientId">The unique identifier of the client for which the feature option is being retrieved. Cannot be null or empty.</param>
    /// <param name="featureFlag">The feature flag representing the specific feature option to retrieve.</param>
    /// <returns>The integer value of the feature option if it is defined and can be parsed as an integer;  otherwise, <see
    /// langword="null"/>.</returns>
    public static int? GetFeatureOptionInt(string clientId, ClientFeatures.Flags featureFlag)
    {
        var option = GetFeatureOption(clientId, featureFlag);
        if (option == null) return null;
        if (int.TryParse(option, out var value))
            return value;
        return null; // or throw an exception if you prefer
    }

    /// <summary>
    /// Updates the configuration options for a specific feature flag associated with a client.
    /// </summary>
    /// <remarks>This method updates the options for a feature flag in the database for the specified client.
    /// If the client or feature flag does not exist, no changes will be made.</remarks>
    /// <param name="clientId">The unique identifier of the client. This value must not be null or empty.</param>
    /// <param name="featureFlag">The feature flag to update. This value determines which feature's options will be modified.</param>
    /// <param name="options">The new configuration options for the specified feature flag. This value must not be null.</param>
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
