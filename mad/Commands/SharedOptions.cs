using mad.Common;
using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace mad.Commands;

internal static class SharedOptions
{
    public static Option<string> AdminUrl
    {
        get
        {
            var opt = new Option<string>("--admin-url", "Base URL of the admin server");
            opt.SetDefaultValueFactory(() => AuthUtils.TryLoadAdminUrl() ?? "http://localhost:9041"); // fallback
            return opt;
        }
    }

    public static readonly Option<string> AdminToken =
        new("--admin-token", "Admin bearer token (optional, falls back to ~/.mad_token)");

    public static Option<string> AdminUsername =>
        new("--admin-username", "Admin username for login");

    public static Option<string> AdminPassword =>
        new("--admin-password", "Admin password for login");

    public static Option<bool> OutputJson =>
        new("--json", "Output result as raw JSON");
}
