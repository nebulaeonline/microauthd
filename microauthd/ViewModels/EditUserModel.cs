using madTypes.Api.Common;
using System.ComponentModel.DataAnnotations;

namespace microauthd.ViewModels;

public class EditUserModel
{
    public string Id { get; set; } = string.Empty;

    [Required(ErrorMessage = "Username is required")]
    [StringLength(100, MinimumLength = 3, ErrorMessage = "Username must be at least 3 characters long.")]
    public string Username { get; set; } = string.Empty;

    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email address format.")]
    public string Email { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public bool IsActive { get; set; } = true;

    public DateTime? LockoutUntil { get; set; }

    [Display(Name = "Permanent Lockout")]
    public bool PermanentLockout { get; set; }

    public UserObject ToUserObject()
    {
        return new UserObject
        {
            Id = Id,
            Username = Username,
            Email = Email,
            CreatedAt = CreatedAt,
            IsActive = IsActive,
            LockoutUntil = PermanentLockout ? DateTime.MaxValue : LockoutUntil
        };
    }

    public static EditUserModel FromUserObject(UserObject user)
    {
        return new EditUserModel
        {
            Id = user.Id,
            Username = user.Username,
            Email = user.Email,
            CreatedAt = user.CreatedAt,
            IsActive = user.IsActive,
            LockoutUntil = user.LockoutUntil == DateTime.MaxValue ? null : user.LockoutUntil,
            PermanentLockout = user.LockoutUntil == DateTime.MaxValue
        };
    }
}