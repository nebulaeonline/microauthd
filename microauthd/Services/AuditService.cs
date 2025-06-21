using madTypes.Api.Responses;
using madTypes.Common;
using microauthd.Data;
using Microsoft.AspNetCore.Http;
using Serilog;

namespace microauthd.Services
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
            try
            {
                var logs = AuditStore.GetAuditLogs(userId, action, limit);
                return ApiResult<List<AuditLogResponse>>.Ok(logs);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error retrieving audit logs");
                return ApiResult<List<AuditLogResponse>>.Fail("An error occurred while retrieving audit logs.", 500);
            }
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
            try
            {
                var log = AuditStore.GetAuditLogById(id);

                return log is not null
                    ? ApiResult<AuditLogResponse>.Ok(log)
                    : ApiResult<AuditLogResponse>.NotFound("Audit log not found");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error retrieving audit log by ID: {Id}", id);
                return ApiResult<AuditLogResponse>.Fail("An error occurred while retrieving the audit log.", 500);
            }   
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
            try
            {
                var isoCutoff = DateTime.UtcNow.Subtract(cutoff).ToString("o");
                var purged = AuditStore.PurgeAuditLogs(isoCutoff);
                return ApiResult<MessageResponse>.Ok(new MessageResponse(true, $"Purged {purged} audit log(s)."));
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error purging audit logs older than {Cutoff}", cutoff);
                return ApiResult<MessageResponse>.Fail("An error occurred while purging audit logs.", 500);
            }
        }
    }

}
