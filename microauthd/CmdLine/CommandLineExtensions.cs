using System.CommandLine;
using System.CommandLine.Parsing;

namespace microauthd.CmdLine;

public static class CommandLineExtensions
{
    public static bool WasOptionSpecified<T>(this ParseResult result, Option<T> option)
    {
        var symbolResult = result.FindResultFor(option);
        return symbolResult is OptionResult o && !o.IsImplicit;
    }
}
