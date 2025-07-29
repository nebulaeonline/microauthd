using madTypes.Api.Common;
using System.ComponentModel.DataAnnotations;

namespace microauthd.ViewModels;

public class EditExternalIdpModel
{
    public string Id { get; set; } = string.Empty;

    [Required]
    public string ClientId { get; set; } = string.Empty;

    [Required]
    [StringLength(50, MinimumLength = 2)]
    public string ProviderKey { get; set; } = string.Empty;

    [Required]
    [Display(Name = "Display Name")]
    public string DisplayName { get; set; } = string.Empty;

    [Required]
    [Url(ErrorMessage = "Must be a valid URL")]
    public string Issuer { get; set; } = string.Empty;

    [Required]
    [Display(Name = "Client Identifier")]
    public string ClientIdentifier { get; set; } = string.Empty;

    [Required]
    public string Scopes { get; set; } = "openid email profile";

    public static EditExternalIdpModel FromDto(ExternalIdpProviderDto dto) => new()
    {
        Id = dto.Id,
        ClientId = dto.ClientId,
        ProviderKey = dto.ProviderKey,
        DisplayName = dto.DisplayName,
        Issuer = dto.Issuer,
        ClientIdentifier = dto.ClientIdentifier,
        Scopes = dto.Scopes
    };

    public ExternalIdpProviderDto ToDto() => new()
    {
        Id = Id,
        ClientId = ClientId,
        ProviderKey = ProviderKey,
        DisplayName = DisplayName,
        Issuer = Issuer,
        ClientIdentifier = ClientIdentifier,
        Scopes = Scopes
    };
}

