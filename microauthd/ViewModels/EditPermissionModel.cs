using madTypes.Api.Common;
using Microsoft.AspNetCore.Antiforgery;
using System.ComponentModel.DataAnnotations;

namespace microauthd.ViewModels;

public class EditPermissionModel
{
    public string Id { get; set; } = string.Empty;
    
    [Required]
    [StringLength(255, MinimumLength = 1, ErrorMessage = "Permission name must be between 1 and 255 characters long.")]
    public string Name { get; set; } = string.Empty;
    
    public static EditPermissionModel FromPermissionObject(PermissionObject permission)
    {
        return new EditPermissionModel
        {
            Id = permission.Id,
            Name = permission.Name
        };
    }
    
    public PermissionObject ToPermissionObject()
    {
        return new PermissionObject
        {
            Id = Id,
            Name = Name
        };
    }
}
