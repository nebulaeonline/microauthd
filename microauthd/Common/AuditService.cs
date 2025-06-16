using madTypes.Api.Responses;
using Microsoft.AspNetCore.Http;

namespace microauthd.Common
{
    public static class AuditService
    {
        /// <summary>
        /// Retrieves a list of audit logs based on the specified filters.
        /// </summary>
        /// <remarks>The audit logs are ordered by timestamp in descending order, with the most recent
        /// logs appearing first.</remarks>
        /// <param name="userId">The ID of the user to filter the audit logs by. If <see langword="null"/>, no filtering is applied by user
        /// ID.</param>
        /// <param name="action">The action type to filter the audit logs by. If <see langword="null"/>, no filtering is applied by action
        /// type.</param>
        /// <param name="limit">The maximum number of audit logs to retrieve. Must be a positive integer. Defaults to 100.</param>
        /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="AuditLogResponse"/> objects that match the
        /// specified filters. If no logs match the filters, the list will be empty.</returns>
        public static ApiResult<List<AuditLogResponse>> GetAuditLogs(string? userId = null, string? action = null, int limit = 100)
        {
            var logs = Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                var where = new List<string>();
                if (!string.IsNullOrWhiteSpace(userId)) where.Add("user_id = $uid");
                if (!string.IsNullOrWhiteSpace(action)) where.Add("action = $act");

                cmd.CommandText = $"""
                    SELECT id, user_id, action, target, timestamp, ip_address, user_agent
                    FROM audit_logs
                    {(where.Count > 0 ? $"WHERE {string.Join(" AND ", where)}" : "")}
                    ORDER BY timestamp DESC
                    LIMIT $limit;
                """;

                if (!string.IsNullOrWhiteSpace(userId))
                    cmd.Parameters.AddWithValue("$uid", userId);
                if (!string.IsNullOrWhiteSpace(action))
                    cmd.Parameters.AddWithValue("$act", action);
                cmd.Parameters.AddWithValue("$limit", limit);

                using var reader = cmd.ExecuteReader();
                var list = new List<AuditLogResponse>();
                while (reader.Read())
                {
                    list.Add(new AuditLogResponse
                    {
                        Id = reader.GetString(0),
                        UserId = reader.IsDBNull(1) ? null : reader.GetString(1),
                        Action = reader.GetString(2),
                        Target = reader.IsDBNull(3) ? null : reader.GetString(3),
                        Timestamp = reader.GetString(4),
                        IpAddress = reader.IsDBNull(5) ? null : reader.GetString(5),
                        UserAgent = reader.IsDBNull(6) ? null : reader.GetString(6),
                    });
                }
                return list;
            });

            return ApiResult<List<AuditLogResponse>>.Ok(logs);
        }

        /// <summary>
        /// Retrieves an audit log entry by its unique identifier.
        /// </summary>
        /// <remarks>This method queries the database for an audit log entry with the specified
        /// identifier. If the entry exists, it is returned as part of a successful <see cref="ApiResult{T}"/>. If no
        /// entry is found, the result indicates a "not found" status. The method does not return null.</remarks>
        /// <param name="id">The unique identifier of the audit log entry to retrieve. Cannot be null or empty.</param>
        /// <returns>An <see cref="ApiResult{T}"/> containing the <see cref="AuditLogResponse"/> if the audit log entry is found;
        /// otherwise, an <see cref="ApiResult{T}"/> indicating that the entry was not found.</returns>
        public static ApiResult<AuditLogResponse> GetAuditLogById(string id)
        {
            var log = Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    SELECT id, user_id, action, target, timestamp, ip_address, user_agent
                    FROM audit_logs
                    WHERE id = $id;
                """;
                cmd.Parameters.AddWithValue("$id", id);

                using var reader = cmd.ExecuteReader();
                if (!reader.Read()) return null;

                return new AuditLogResponse
                {
                    Id = reader.GetString(0),
                    UserId = reader.IsDBNull(1) ? null : reader.GetString(1),
                    Action = reader.GetString(2),
                    Target = reader.IsDBNull(3) ? null : reader.GetString(3),
                    Timestamp = reader.GetString(4),
                    IpAddress = reader.IsDBNull(5) ? null : reader.GetString(5),
                    UserAgent = reader.IsDBNull(6) ? null : reader.GetString(6),
                };
            });

            return log is not null
                ? ApiResult<AuditLogResponse>.Ok(log)
                : ApiResult<AuditLogResponse>.NotFound("Audit log not found");
        }

        /// <summary>
        /// Deletes audit log entries that are older than the specified cutoff duration.
        /// </summary>
        /// <remarks>This method removes entries from the audit log database table where the timestamp is
        /// earlier than the calculated cutoff time. The operation is performed using a database connection and executes
        /// a single SQL DELETE statement.</remarks>
        /// <param name="cutoff">A <see cref="TimeSpan"/> representing the duration to retain logs.  Logs with timestamps older than the
        /// current UTC time minus this duration will be purged.</param>
        /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the number of audit
        /// logs purged.</returns>
        public static ApiResult<MessageResponse> PurgeLogsOlderThan(TimeSpan cutoff)
        {
            var isoCutoff = DateTime.UtcNow.Subtract(cutoff).ToString("o");
            var purged = Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "DELETE FROM audit_logs WHERE timestamp < $ts;";
                cmd.Parameters.AddWithValue("$ts", isoCutoff);
                return cmd.ExecuteNonQuery();
            });

            return ApiResult<MessageResponse>.Ok(new MessageResponse($"Purged {purged} audit log(s)."));
        }
    }

}
