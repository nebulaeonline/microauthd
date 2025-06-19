using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace madTypes.Api.Responses
{
    public class VersionResponse
    {
        [JsonPropertyName("name")]
        public string Name { get; } = "microauthd";
        [JsonPropertyName("version")]
        public string Version =>
            typeof(VersionResponse).Assembly.GetName().Version?.ToString() ?? "unknown";
    }
}
