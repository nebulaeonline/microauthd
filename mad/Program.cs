using System.CommandLine;
using mad.Commands;

namespace mad;

internal class Program
{
    static async Task<int> Main(string[] args)
    {
        var root = new RootCommand("mad - microauthd CLI");

        root.AddCommand(UserCommands.Build());
        root.AddCommand(SessionCommands.Build());
        root.AddCommand(RoleCommands.Build());
        root.AddCommand(PermissionCommands.Build());
        root.AddCommand(ClientCommands.Build());
        root.AddCommand(ScopeCommands.Build());
        return await root.InvokeAsync(args);
    }
}
