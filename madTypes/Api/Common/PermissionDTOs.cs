using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace madTypes.Api.Common;

public class PermissionDto
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;
}

public class PermissionAssignmentDto
{
    [JsonPropertyName("roleId")]
    public string RoleId { get; set; } = string.Empty;

    [JsonPropertyName("permissions")]
    public List<PermissionDto> Permissions { get; set; } = new();
}
