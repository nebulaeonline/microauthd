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

        var UserToUpdate = UserForm!.ToUserObject();

        var result = UserService.UpdateUser(UserToUpdate.Id, UserToUpdate, Config);
        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Update failed.");
            return Page();
        }

        return RedirectToPage("/Admin/Users/Index");
    }

    public IActionResult OnPostDelete()
    {
        if (string.IsNullOrWhiteSpace(UserForm?.Id))
            return RedirectToPage("/Admin/Users/Index");

        var result = UserService.DeleteUser(UserForm.Id, Config, UserId, IpAddress, UserAgent);

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Delete failed.");
            return Page();
        }

        TempData["Success"] = "User permanently deleted.";
        return RedirectToPage("/Admin/Users/Index");
    }
}