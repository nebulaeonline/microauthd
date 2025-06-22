using madTypes.Api.Common;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace microauthd.ViewModels;

public class EditScopeModel
{
    public string Id { get; init; } = string.Empty;
    [Required]
    [StringLength(255, MinimumLength = 1, ErrorMessage = "Name must be between 1 and 255 characters.")]
    public string Name { get; init; } = string.Empty;
    [StringLength(1024, ErrorMessage = "Description must be up to 1024 characters long.")]
    public string? Description { get; init; }
    public bool IsActive { get; init; }
    public bool IsProtected { get; init; } = false;
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;

    public static EditScopeModel FromScopeObject(ScopeObject scope)
    {
        return new EditScopeModel
        {
            Id = scope.Id,
            Name = scope.Name,
            Description = scope.Description,
            IsProtected = scope.IsProtected,
            IsActive = scope.IsActive,
            CreatedAt = scope.CreatedAt
        };
    }

    public ScopeObject ToScopeObject()
    {
        return new ScopeObject
        {
            Id = Id,
            Name = Name,
            Description = Description,
            IsProtected = IsProtected,
            IsActive = IsActive,
            CreatedAt = CreatedAt
        };
    }
}
