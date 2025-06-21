using madTypes.Api.Common;
using System.ComponentModel.DataAnnotations;

namespace microauthd.ViewModels;

public class EditRoleModel
{
    public string Id { get; set; } = string.Empty;
    [Required]
    [StringLength(100, MinimumLength = 1, ErrorMessage = "Role name must be between 1 and 100 characters.")]
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsProtected { get; set; } = false;
    public bool IsActive { get; set; } = true;

    public EditRoleModel FromRoleObject(RoleObject role)
    {
        return new EditRoleModel
        {
            Id = role.Id,
            Name = role.Name,
            Description = role.Description,
            IsProtected = role.IsProtected,
            IsActive = role.IsActive
        };
    }

    public RoleObject ToRoleObject()
    {
        return new RoleObject
        {
            Id = Id,
            Name = Name,
            Description = Description,
            IsProtected = IsProtected,
            IsActive = IsActive
        };
    }
}
