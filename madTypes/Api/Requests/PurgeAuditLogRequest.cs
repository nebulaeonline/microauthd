using System.Text.Json.Serialization;

namespace madTypes.Api.Requests;

public record PurgeAuditLogRequest(
    [property: JsonPropertyName("older_than_days")]
    int OlderThanDays
);
