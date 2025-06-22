using madTypes.Api.Common;
using microauthd.Common;
using microauthd.Data;
using microauthd.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc;

namespace microauthd.Pages.Admin.Clients;

[Authorize(Roles = Constants.MadAdmin)]
public class IndexModel : BasePageModel
{
    public List<ClientObject> Clients { get; private set; } = new();
    public int TotalCount { get; private set; }
    public int CurrentPage { get; private set; }
    public int PageSize { get; private set; } = 10;

    public void OnGet(int pg = 1, int pageSize = 10)
    {
        PageSize = pageSize;
        CurrentPage = pg < 1 ? 1 : pg;
        var offset = (CurrentPage - 1) * PageSize;

        Clients = ClientStore.ListClients(offset, PageSize);
        TotalCount = ClientService.GetClientCount();
    }
}
