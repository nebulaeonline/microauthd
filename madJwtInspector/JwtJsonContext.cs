using System.Text.Json;
using System.Text.Json.Serialization;

namespace madJwtInspector;

[JsonSerializable(typeof(JwtIntrospectionResult))]
[JsonSerializable(typeof(Dictionary<string, JsonElement>))]
public partial class JwtJsonContext : JsonSerializerContext { }
