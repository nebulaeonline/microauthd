namespace madTypes.Api.Responses
{
    public class RoleResponse
    {
        public string Id { get; set; } = default!;
        public string Name { get; set; } = default!;
        public string? Description { get; set; }
        public bool IsProtected { get; set; }
    }
}
