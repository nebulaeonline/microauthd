using System.Text.Json.Serialization;

namespace madTypes.Api.Requests;

public class SetUserLockoutRequest
{
    [JsonPropertyName("lockout_until")]
    public DateTime LockoutUntil { get; set; }
}