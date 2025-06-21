using madTypes.Api.Responses;
using System;
using System.Collections.Generic;

namespace microauthd.Data;

public static class AuditStore
{
    /// <summary>
    /// Retrieves a list of audit logs, optionally filtered by user ID and action.
    /// </summary>
    /// <remarks>This method queries the audit logs stored in the database and applies optional
    /// filters  based on the provided <paramref name="userId"/> and <paramref name="action"/> parameters.  If no
    /// filters are specified, all audit logs are retrieved up to the specified <paramref name="limit"/>.</remarks>
    /// <param name="userId">The ID of the user whose audit logs should be retrieved. If <see langword="null"/> or empty,  logs for all
    /// users are included.</param>
    /// <param name="action">The action type to filter the audit logs by. If <see langword="null"/> or empty,  logs for all actions are
    /// included.</param>
    /// <param name="limit">The maximum number of audit logs to retrieve. Must be a positive integer. Defaults to 100.</param>
    /// <returns>A list of <see cref="AuditLogResponse"/> objects representing the audit logs.  The list is ordered by
    /// timestamp in descending order.</returns>
    public static List<AuditLogResponse> GetAuditLogs(string? userId = null, string? action = null, int limit = 100)
    {
        return Db.WithConnection(conn =>
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
    }

    /// <summary>
    /// Retrieves an audit log entry by its unique identifier.
    /// </summary>
    /// <remarks>This method queries the database for an audit log entry matching the specified
    /// identifier.  If no matching entry is found, the method returns <see langword="null"/>.</remarks>
    /// <param name="id">The unique identifier of the audit log entry to retrieve. Cannot be null or empty.</param>
    /// <returns>An <see cref="AuditLogResponse"/> object containing the details of the audit log entry if found;  otherwise,
    /// <see langword="null"/>.</returns>
    public static AuditLogResponse? GetAuditLogById(string id)
    {
        return Db.WithConnection(conn =>
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
    }

    /// <summary>
    /// Deletes audit log entries that are older than the specified cutoff time.
    /// </summary>
    /// <remarks>This method executes a database operation to remove audit log entries based on the provided
    /// cutoff duration. Ensure that the database connection is properly configured and accessible before calling this
    /// method.</remarks>
    /// <param name="isoCutoff">A <see cref="TimeSpan"/> representing the cutoff duration. Audit log entries with timestamps older than the
    /// current time minus this duration will be purged.</param>
    /// <returns>The number of audit log entries that were deleted.</returns>
    public static int PurgeAuditLogs(string isoCutoff)
    {
        var purged = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM audit_logs WHERE timestamp < $ts;";
            cmd.Parameters.AddWithValue("$ts", isoCutoff);
            return cmd.ExecuteNonQuery();
        });

        return purged;
    }
}
