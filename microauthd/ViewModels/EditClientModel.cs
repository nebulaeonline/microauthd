using madTypes.Api.Common;
using madTypes.Api.Requests;
using microauthd.Data;

using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace microauthd.ViewModels
{
    public class EditClientModel
    {
        public string Id { get; init; } = string.Empty;
        [Required]
        [StringLength(255, MinimumLength = 1, ErrorMessage = "Client identifier must have between 1-255 characters.")]
        public string ClientId { get; init; } = string.Empty;
        [Required]
        [StringLength(255, MinimumLength = 1, ErrorMessage = "Display name must have between 1-255 characters.")]
        public string DisplayName { get; init; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public string ClientSecretHash { get; init; } = string.Empty;
        public bool IsActive { get; init; }
        public DateTime CreatedAt { get; init; } = DateTime.MinValue;
        [Required]
        [StringLength(64, MinimumLength = 1, ErrorMessage = "Audience must have between 1-64 characters.")]
        public string Audience { get; init; } = "microauthd";

        public static EditClientModel FromClientObject(ClientObject client)
        {
            return new EditClientModel
            {
                Id = client.Id,
                ClientId = client.ClientId,
                DisplayName = client.DisplayName,
                IsActive = client.IsActive,
                CreatedAt = client.CreatedAt,
                Audience = client.Audience
            };
        }

        public static EditClientModel FromClient(Client client)
        {
            return new EditClientModel
            {
                Id = client.Id,
                ClientId = client.ClientId,
                DisplayName = client.DisplayName,
                ClientSecretHash = client.ClientSecretHash,
                IsActive = client.IsActive,
                Audience = client.Audience
            };
        }

        public static EditClientModel FromCreateClientRequest(CreateClientRequest request)
        {
            return new EditClientModel
            {
                ClientId = request.ClientId,
                DisplayName = request.DisplayName,
                ClientSecret = request.ClientSecret,
                Audience = request.Audience
            };
        }

        public ClientObject ToClientObject()
        {
            return new ClientObject
            {
                Id = Id,
                ClientId = ClientId,
                DisplayName = DisplayName,
                IsActive = IsActive,
                CreatedAt = CreatedAt,
                Audience = Audience
            };
        }

        public Client ToClient()
        {
            return new Client
            {
                Id = Id,
                ClientId = ClientId,
                DisplayName = DisplayName,
                ClientSecretHash = ClientSecretHash,
                IsActive = IsActive,
                Audience = Audience
            };
        }

        public CreateClientRequest ToClientRequest()
        {
            return new CreateClientRequest
            {
                ClientId = ClientId,
                ClientSecret = ClientSecret,
                DisplayName = DisplayName,
                Audience = Audience
            };
        }
    }
}
