using madTypes.Common;
using microauthd.Data;
using Serilog;

namespace microauthd.Services
{
    public static class ClientFeaturesService
    {
        /// <summary>
        /// Sets the specified feature flag for a client, enabling or disabling it based on the provided value.
        /// </summary>
        /// <remarks>This method attempts to set the feature flag for the specified client. If an error
        /// occurs during the operation,  it logs a warning and returns <see langword="false"/>. Ensure that the
        /// <paramref name="clientId"/> and  <paramref name="featureFlag"/> are valid before calling this
        /// method.</remarks>
        /// <param name="clientId">The unique identifier of the client for which the feature flag is being set. Cannot be null or empty.</param>
        /// <param name="featureFlag">The feature flag to be set for the client.</param>
        /// <param name="isEnabled">A value indicating whether the feature flag should be enabled (<see langword="true"/>) or disabled (<see
        /// langword="false"/>).</param>
        /// <param name="options">Optional configuration settings for the feature flag. Defaults to an empty string if not provided.</param>
        /// <returns><see langword="true"/> if the feature flag was successfully set; otherwise, <see langword="false"/> if an
        /// error occurred.</returns>
        public static bool SetClientFeatureFlag(string clientId, ClientFeatures.Flags featureFlag, bool isEnabled, string options = "")
        {
            try
            {
                ClientFeaturesStore.SetClientFeatureFlag(clientId, featureFlag, isEnabled, options);
                return true;
            }
            catch (Exception ex)
            {
                // Log the exception (logging mechanism not shown here)
                Log.Warning(ex, "Failed to set client feature flag for client {ClientId}, feature {FeatureFlag}", clientId, featureFlag);
                return false;
            }
        }

        /// <summary>
        /// Sets the specified feature option for a given client.
        /// </summary>
        /// <remarks>This method attempts to set the feature option for the specified client and feature
        /// flag. If an error occurs during the operation, the method logs the exception and returns <see
        /// langword="false"/>.</remarks>
        /// <param name="clientId">The unique identifier of the client for which the feature option is being set. Cannot be null or empty.</param>
        /// <param name="featureFlag">The feature flag representing the specific feature to configure.</param>
        /// <param name="options">The configuration options to apply to the specified feature. Cannot be null or empty.</param>
        /// <returns><see langword="true"/> if the feature option was successfully set; otherwise, <see langword="false"/>.</returns>
        public static bool SetFeatureOption(string clientId, ClientFeatures.Flags featureFlag, string options)
        {
            try
            {
                ClientFeaturesStore.SetFeatureOption(clientId, featureFlag, options);
                return true;
            }
            catch (Exception ex)
            {
                // Log the exception (logging mechanism not shown here)
                Log.Warning(ex, "Failed to set feature option for client {ClientId}, feature {FeatureFlag}", clientId, featureFlag);
                return false;
            }
        }

        /// <summary>
        /// Determines whether a specified feature is enabled for a given client.
        /// </summary>
        /// <remarks>If an error occurs while checking the feature's status, the method logs the exception
        /// and returns <see langword="false"/>.</remarks>
        /// <param name="clientId">The unique identifier of the client for which the feature's status is being checked. Cannot be <see
        /// langword="null"/> or empty.</param>
        /// <param name="featureFlag">The feature flag representing the feature to check. Must be a valid flag defined in <see
        /// cref="ClientFeatures.Flags"/>.</param>
        /// <returns><see langword="true"/> if the specified feature is enabled for the given client; otherwise, <see
        /// langword="false"/>.</returns>
        public static bool IsFeatureEnabled(string clientId, ClientFeatures.Flags featureFlag)
        {
            try
            {
                var isEnabled = ClientFeaturesStore.IsFeatureEnabled(clientId, featureFlag);

                if (isEnabled is null or false)
                    return false;

                return true;
            }
            catch (Exception ex)
            {
                // Log the exception (logging mechanism not shown here)
                Log.Warning(ex, "Failed to check if feature is enabled for client {ClientId}, feature {FeatureFlag}", clientId, featureFlag);
                return false;
            }
        }

        /// <summary>
        /// Retrieves the feature option value for a specified client and feature flag.
        /// </summary>
        /// <remarks>This method attempts to retrieve the feature option from the underlying store. If an
        /// error occurs during retrieval, the exception is logged, and <see langword="null"/> is returned.</remarks>
        /// <param name="clientId">The unique identifier of the client for which the feature option is being retrieved. Must not be null or
        /// empty.</param>
        /// <param name="featureFlag">The feature flag representing the specific feature option to retrieve.</param>
        /// <returns>A string representing the feature option value for the specified client and feature flag. Returns <see
        /// langword="null"/> if the feature option cannot be retrieved or an error occurs.</returns>
        public static string? GetFeatureOption(string clientId, ClientFeatures.Flags featureFlag)
        {
            try
            {
                return ClientFeaturesStore.GetFeatureOption(clientId, featureFlag);
            }
            catch (Exception ex)
            {
                // Log the exception (logging mechanism not shown here)
                Log.Warning(ex, "Failed to get feature option for client {ClientId}, feature {FeatureFlag}", clientId, featureFlag);
                return null;
            }
        }
    }
}
