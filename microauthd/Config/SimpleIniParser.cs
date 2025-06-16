namespace microauthd.Config;

public static class SimpleIniParser
{
    public static Dictionary<string, string> Parse(string path)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var line in File.ReadLines(path))
        {
            var trimmed = line.Trim();

            if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith('#') || trimmed.StartsWith(';'))
                continue;

            int idx = trimmed.IndexOf('=');
            if (idx <= 0) continue;

            string key = trimmed[..idx].Trim();
            string valuePart = trimmed[(idx + 1)..].Trim();

            // Strip inline comment if not quoted
            string value;
            if (valuePart.StartsWith('"') && valuePart.EndsWith('"'))
            {
                // quoted string, strip quotes but keep any inline comment
                value = valuePart[1..^1];
            }
            else
            {
                // unquoted: remove comment at first # or ;
                int commentIdx = valuePart.IndexOfAny(new[] { '#', ';' });
                if (commentIdx >= 0)
                    valuePart = valuePart[..commentIdx].Trim();

                value = valuePart;
            }

            dict[key] = value;
        }

        return dict;
    }
}
