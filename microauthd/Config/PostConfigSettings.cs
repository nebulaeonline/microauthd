namespace microauthd.Config
{
    public class PostConfigSettings
    {
        public string AdminUsername { get; init; } = string.Empty;
        public string AdminPassword { get; init; } = string.Empty;
        public string AdminEmail { get; init; } = string.Empty;

        public string InitialOidcClientId { get; init; } = string.Empty;
        public string InitialOidcClientSecret { get; init; } = string.Empty;
        public string InitialOidcAudience { get; init; } = string.Empty;

        public bool NeedsAdminCreation => !string.IsNullOrWhiteSpace(AdminUsername);
        public bool NeedsOidcClientCreation => !string.IsNullOrWhiteSpace(InitialOidcClientId);
    }
}
