namespace mad.Api.Responses
{
    public class UserResponse
    {
        public required string Id { get; set; }
        public required string Username { get; set; }
        public required string Email { get; set; }
        public required string CreatedAt { get; set; }
        public bool IsActive { get; set; }
    }
}
