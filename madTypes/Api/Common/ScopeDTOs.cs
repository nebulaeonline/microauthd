using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace madTypes.Api.Common;

public class ScopeDto
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
}

public class ScopeAssignmentDto
{
    public string TargetId { get; set; } = string.Empty;
    public List<ScopeDto> Scopes { get; set; } = new();
}
