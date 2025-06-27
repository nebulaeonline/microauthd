using madTypes.Api.Common;
using microauthd.Common;
using microauthd.Data;
using microauthd.Services;
using microauthd.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
namespace microauthd.Pages.Admin.Users;

[Authorize(Roles = Constants.MadAdmin)]
public class EditModel : BasePageModel
{
    [BindProperty]
    public EditUserModel? UserForm { get; set; } = null;
    public DateTime? LockoutUntil { get; set; }

    [Display(Name = "Permanent Lockout")]
    public bool PermanentLockout { get; set; }
    public IActionResult OnGet(string? id)
    {
        if (string.IsNullOrWhiteSpace(id))
            return RedirectToPage("/Admin/Users/Index");

        var user = UserStore.GetUserById(id);
        if (user == null)
            return NotFound();

        UserForm = EditUserModel.FromUserObject(user);

        return Page();
    }

    public IActionResult OnPost()
    {
        if (!ModelState.IsValid)
            return Page();

        // Translate Razor input to full UserObject
        var userToUpdate = UserForm!.ToUserObject();

        // Handle permanent lockout logic
        if (UserForm.PermanentLockout)
            userToUpdate.LockoutUntil = DateTime.MaxValue;

        if (userToUpdate.LockoutUntil.HasValue && userToUpdate.LockoutUntil.Value < DateTime.UtcNow)
        {
            ModelState.AddModelError(nameof(UserForm.LockoutUntil), "Lockout time must be in the future.");
            return Page();
        }

        var result = UserService.UpdateUser(userToUpdate.Id, userToUpdate, Config);
        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Update failed.");
            return Page();
        }

        TempData["Success"] = "User updated successfully.";
        return RedirectToPage("/Admin/Users/Index");
    }

    public IActionResult OnPostDelete()
    {
        if (string.IsNullOrWhiteSpace(UserForm?.Id))
            return RedirectToPage("/Admin/Users/Index");

        var result = UserService.DeleteUser(UserForm.Id, Config);

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Delete failed.");
            return Page();
        }

        TempData["Success"] = "User permanently deleted.";
        return RedirectToPage("/Admin/Users/Index");
    }
}