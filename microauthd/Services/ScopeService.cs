using madTypes.Api.Common;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using madTypes.Common;
using microauthd.Common;
using microauthd.Config;
using microauthd.Data;
using Microsoft.Data.Sqlite;
using Serilog;

namespace microauthd.Services;

public static class ScopeService
{
    /// <summary>
    /// Creates a new scope with the specified name and description.
    /// </summary>
    /// <remarks>This method validates the scope name before attempting to create the scope. If the name is
    /// invalid, the operation fails immediately. If a scope with the same name already exists, the operation fails and
    /// returns an appropriate error message. The method also logs the operation for auditing purposes if the optional
    /// auditing parameters are provided.</remarks>
    /// <param name="req">The request containing the name and description of the scope to create. The <see cref="ScopeObject.Name"/>
    /// must be non-empty, alphanumeric, and may include hyphens or underscores.</param>
    /// <param name="actorUserId">The optional ID of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ip">The optional IP address of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ua">The optional user agent string of the user performing the operation, used for auditing purposes.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/>.  If the operation succeeds, the result
    /// indicates success and includes a message confirming the creation of the scope.  If the operation fails, the
    /// result indicates failure and includes an error message.</returns>
    public static ApiResult<ScopeObject> CreateScope(
        ScopeObject req,
        AppConfig config)
    {
        if (!Utils.IsValidTokenName(req.Name))
            return ApiResult<ScopeObject>.Fail("Invalid scope name: must be non-empty, and cannot contain whitespace.", 400);

        var scopeId = Guid.NewGuid().ToString();

        try
        {
            var scopeObj = ScopeStore.CreateScope(scopeId, req);

            if (scopeObj is null)
                return ApiResult<ScopeObject>.Fail("Scope creation failed (duplicate name?)", 400);

            if (config.EnableAuditLogging) 
                Utils.Audit.Logg("create_scope", req.Name, scopeId);

            return ApiResult<ScopeObject>.Ok(scopeObj);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to create scope {ScopeName}", req.Name);
            return ApiResult<ScopeObject>.Fail("Internal error occurred while creating scope", 500);
        }
    }

    /// <summary>
    /// Updates an existing scope with the specified details.
    /// </summary>
    /// <remarks>The method performs validation on the provided scope details, ensuring the name is valid and
    /// does not conflict with existing scopes. If the update is successful, the updated scope is retrieved and
    /// returned. If the update fails or the scope cannot be retrieved, an error result is returned.</remarks>
    /// <param name="id">The unique identifier of the scope to update.</param>
    /// <param name="updated">The updated scope details. The <see cref="ScopeObject.Name"/> property must be a valid token identifier and
    /// cannot be null or whitespace.</param>
    /// <param name="config">The application configuration used for the operation.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the updated <see cref="ScopeObject"/> if the operation succeeds;
    /// otherwise, an <see cref="ApiResult{T}"/> with an error message describing the failure.</returns>
    public static ApiResult<ScopeObject> UpdateScope(
        string id,
        ScopeObject updated,
        AppConfig config
    )
    {
        if (string.IsNullOrWhiteSpace(updated.Name))
            return ApiResult<ScopeObject>.Fail("Scope name is required.", 400);

        if (!Utils.IsValidTokenName(updated.Name))
            return ApiResult<ScopeObject>.Fail("Scope name must be a valid token identifier.", 400);

        try
        {
            // Check for name collision
            var conflict = ScopeStore.DoesScopeNameExist(id, updated.Name);

            if (conflict)
                return ApiResult<ScopeObject>.Fail("Another scope already uses that name.", 400);

            var scopeObj = ScopeStore.UpdateScope(id, updated);

            if (scopeObj is null)
                return ApiResult<ScopeObject>.Fail("Scope update failed or not found.", 400);

            return ApiResult<ScopeObject>.Ok(scopeObj);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to update scope {ScopeId}", id);
            return ApiResult<ScopeObject>.Fail("Internal error occurred while updating scope", 500);
        }
    }

    /// <summary>
    /// Retrieves a list of all active scopes from the database.
    /// </summary>
    /// <remarks>This method queries the database for all scopes that are marked as active and returns them in
    /// ascending order by name. Each scope includes its ID, name, description, creation date, and active
    /// status.</remarks>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="ScopeObject"/> objects representing the active
    /// scopes. If no active scopes are found, the list will be empty.</returns>
    public static ApiResult<List<ScopeObject>> ListAllScopes()
    {
        try
        {
            var scopes = ScopeStore.ListAllScopes();

            return ApiResult<List<ScopeObject>>.Ok(scopes);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to list all scopes");
            return ApiResult<List<ScopeObject>>.Fail("Internal error occurred while listing scopes", 500);
        }
    }

    /// <summary>
    /// Retrieves a scope object by its unique identifier.
    /// </summary>
    /// <remarks>This method queries the database for a scope with the specified identifier. If no matching
    /// scope  is found, the result will indicate a "Not Found" status. The returned <see cref="ScopeObject"/>  includes
    /// the scope's ID, name, and description.</remarks>
    /// <param name="id">The unique identifier of the scope to retrieve. Cannot be null or empty.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the <see cref="ScopeObject"/> if found;  otherwise, an <see
    /// cref="ApiResult{T}"/> indicating that the scope was not found.</returns>
    public static ApiResult<ScopeObject> GetScopeById(string id)
    {
        try
        {
            var scope = ScopeStore.GetScopeById(id);

            return scope is null
                ? ApiResult<ScopeObject>.NotFound($"Scope '{id}' not found.")
                : ApiResult<ScopeObject>.Ok(scope);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error retrieving scope by ID: {ScopeId}", id);
            return ApiResult<ScopeObject>.Fail("Internal error occurred while retrieving scope", 500);
        }
    }

    /// <summary>
    /// Retrieves the unique identifier for a scope based on its name.
    /// </summary>
    /// <remarks>This method attempts to retrieve the scope identifier from the underlying store. If the scope
    /// name does not exist, a failure result with a 404 status code is returned. In the event of an internal error, a
    /// failure result with a 500 status code is returned.</remarks>
    /// <param name="name">The name of the scope to retrieve the identifier for. Cannot be null, empty, or consist solely of whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the scope identifier as a string if the scope is found. If the scope is
    /// not found, the result contains an error message and a 404 status code. If the input is invalid or an internal
    /// error occurs, the result contains an appropriate error message and status code.</returns>
    public static ApiResult<string> GetScopeIdByName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return ApiResult<string>.Fail("Scope name is required", 400);

        try
        {
            var id = ScopeStore.GetScopeIdByName(name);

            return id == null
                ? ApiResult<string>.Fail("Scope not found", 404)
                : ApiResult<string>.Ok(id);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error retrieving scope ID by name");
            return ApiResult<string>.Fail("Internal error occurred", 500);
        }
    }

    /// <summary>
    /// Deletes a scope identified by the specified scope ID from the database.
    /// </summary>
    /// <remarks>This method attempts to delete the specified scope from the database. If the deletion fails, 
    /// an error is logged, and a failure result is returned. If the deletion succeeds, an audit log  entry is created
    /// to record the operation.</remarks>
    /// <param name="scopeId">The unique identifier of the scope to delete. Cannot be null or empty.</param>
    /// <param name="config">The application configuration used for logging and auditing. Cannot be null.</param>
    /// <param name="actorUserId">The ID of the user performing the operation, used for auditing. Optional.</param>
    /// <param name="ip">The IP address of the user performing the operation, used for auditing. Optional.</param>
    /// <param name="ua">The user agent of the user performing the operation, used for auditing. Optional.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success result if the scope was deleted successfully; otherwise, returns a failure result
    /// with an error message.</returns>
    public static ApiResult<MessageResponse> DeleteScope(
        string scopeId,
        AppConfig config)
    {
        try
        {
            var deleted = ScopeStore.DeleteScope(scopeId);

            if (!deleted)
                return ApiResult<MessageResponse>.Fail("Failed to delete scope", 400);

            if (config.EnableAuditLogging) 
                Utils.Audit.Logg("delete_scope", scopeId);

            return ApiResult<MessageResponse>.Ok(new(true, $"Scope '{scopeId}' deleted"));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to delete scope {ScopeId}", scopeId);
            return ApiResult<MessageResponse>.Fail("Internal error occurred while deleting scope", 500);
        }
    }

    /// <summary>
    /// Assigns one or more scopes to a client, ensuring that the scopes are active and valid.
    /// </summary>
    /// <remarks>This method ensures that only active and valid scopes are assigned to the client. Duplicate
    /// or invalid scope IDs are ignored. If no valid scopes are assigned, the method returns a failure result.  The
    /// operation is logged for auditing purposes if <paramref name="actorUserId"/>, <paramref name="ip"/>, or <paramref
    /// name="ua"/> is provided.</remarks>
    /// <param name="clientId">The unique identifier of the client to which the scopes will be assigned. Cannot be null, empty, or whitespace.</param>
    /// <param name="req">The request containing the list of scope IDs to assign. Must include at least one valid scope ID.</param>
    /// <param name="actorUserId">The optional identifier of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ip">The optional IP address of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ua">The optional user agent string of the user performing the operation, used for auditing purposes.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success result if at least one scope was successfully assigned to the client. Returns a
    /// failure result if no scopes were assigned or if the input parameters are invalid.</returns>
    public static ApiResult<MessageResponse> AddScopesToClient(
        string clientId,
        AssignScopesRequest req,
        AppConfig config)
    {
        if (string.IsNullOrWhiteSpace(clientId))
            return ApiResult<MessageResponse>.Fail("Client ID is required", 400);

        if (req.ScopeIds is null || req.ScopeIds.Count == 0)
            return ApiResult<MessageResponse>.Fail("At least one scope ID is required", 400);

        try
        {
            var added = ScopeStore.AddScopesToClient(clientId, req);

            if (added == 0)
                return ApiResult<MessageResponse>.Fail("No scopes were assigned. Check scope IDs or duplicates.", 400);

            if (config.EnableAuditLogging) 
                Utils.Audit.Logg("assign_scope_to_client", clientId, req.ScopeIds.Count.ToString());

            return ApiResult<MessageResponse>.Ok(new(true, $"Assigned {added} scope(s) to client."));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to assign scopes to client {ClientId}", clientId);
            return ApiResult<MessageResponse>.Fail("Internal error occurred while assigning scopes to client", 500);
        }
    }

    /// <summary>
    /// Retrieves the list of active scopes associated with a specified client.
    /// </summary>
    /// <remarks>This method queries the database to retrieve scopes that are both active and associated with
    /// the specified client. The returned scopes include details such as the scope's ID, name, description, creation
    /// date, and active status.</remarks>
    /// <param name="clientId">The unique identifier of the client for which to retrieve scopes. Cannot be null, empty, or whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="ScopeObject"/> objects representing the active
    /// scopes for the client. If the <paramref name="clientId"/> is invalid, the result will indicate failure with an
    /// appropriate error message.</returns>
    public static ApiResult<List<ScopeObject>> GetScopesForClient(string clientId)
    {
        if (string.IsNullOrWhiteSpace(clientId))
            return ApiResult<List<ScopeObject>>.Fail("Client ID is required", 400);

        try
        {
            var scopes = ScopeStore.GetScopesForClient(clientId);

            return ApiResult<List<ScopeObject>>.Ok(scopes);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to retrieve scopes for client {ClientId}", clientId);
            return ApiResult<List<ScopeObject>>.Fail("Internal error occurred while retrieving scopes for client", 500);
        }
    }

    /// <summary>
    /// Removes a specified scope from a client.
    /// </summary>
    /// <param name="clientId">The unique identifier of the client from which the scope will be removed. Cannot be null or whitespace.</param>
    /// <param name="scopeId">The unique identifier of the scope to be removed. Cannot be null or whitespace.</param>
    /// <param name="actorUserId">The optional identifier of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ip">The optional IP address of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ua">The optional user agent string of the user performing the operation, used for auditing purposes.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success result if the scope was successfully removed, or a failure result if the scope was
    /// not assigned or already removed.</returns>
    public static ApiResult<MessageResponse> RemoveScopeFromClient(
        string clientId,
        string scopeId,
        AppConfig config)
    {
        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(scopeId))
            return ApiResult<MessageResponse>.Fail("Client ID and Scope ID are required", 400);

        try
        {
            var affected = ScopeStore.RemoveScopeFromClient(clientId, scopeId);

            if (affected == 0)
                return ApiResult<MessageResponse>.Fail("Scope not assigned or already removed", 400);

            if (config.EnableAuditLogging) 
                Utils.Audit.Logg("remove_scope_from_client", scopeId, clientId);

            return ApiResult<MessageResponse>.Ok(new(true, $"Removed scope '{scopeId}' from client '{clientId}'"));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to remove scope {ScopeId} from client {ClientId}", scopeId, clientId);
            return ApiResult<MessageResponse>.Fail("Internal error occurred while removing scope from client", 500);
        }
    }

    /// <summary>
    /// Retrieves a list of active scopes assigned to a specified user.
    /// </summary>
    /// <remarks>A scope represents a specific permission or access level assigned to a user.  This method
    /// queries the database for active scopes associated with the user and filters out inactive scopes.</remarks>
    /// <param name="userId">The unique identifier of the user whose scopes are to be retrieved. Cannot be null, empty, or whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of scope names assigned to the user.  If the user has no active
    /// scopes, the list will be empty.  Returns a failure result if the <paramref name="userId"/> is invalid.</returns>
    public static ApiResult<List<ScopeObject>> ListScopesForUser(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<List<ScopeObject>>.Fail("User ID is required", 400);

        try
        {
            var scopes = ScopeStore.GetUserScopeObjs(userId);

            return ApiResult<List<ScopeObject>>.Ok(scopes);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to list scopes for user {UserId}", userId);
            return ApiResult<List<ScopeObject>>.Fail("Internal error occurred while listing scopes for user", 500);
        }
    }

    /// <summary>
    /// Assigns one or more scopes to a user, ensuring that the scopes are active and not already assigned.
    /// </summary>
    /// <remarks>This method ensures that only active scopes are assigned to the user. If a scope is already
    /// assigned or does not exist, it will be ignored. The operation is logged for auditing purposes if <paramref
    /// name="actorUserId"/> is provided.</remarks>
    /// <param name="userId">The unique identifier of the user to whom the scopes will be assigned. Cannot be null, empty, or whitespace.</param>
    /// <param name="req">An object containing the list of scope IDs to assign. Must include at least one scope ID.</param>
    /// <param name="actorUserId">The unique identifier of the user performing the operation. Optional.</param>
    /// <param name="ip">The IP address of the actor performing the operation. Optional.</param>
    /// <param name="ua">The user agent string of the actor performing the operation. Optional.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success message if at least one scope was assigned, or an error message if no scopes were
    /// assigned.</returns>
    public static ApiResult<MessageResponse> AddScopesToUser(
        string userId,
        AssignScopesRequest req,
        AppConfig config)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<MessageResponse>.Fail("User ID is required", 400);

        if (req.ScopeIds.Count == 0)
            return ApiResult<MessageResponse>.Fail("At least one scope ID is required", 400);

        try
        {
            var added = ScopeStore.AddScopesToUser(userId, req);

            if (added == 0)
                return ApiResult<MessageResponse>.Fail("No scopes were assigned — check if they exist or were already assigned", 400);

            if (config.EnableAuditLogging) 
                Utils.Audit.Logg("assign_scope_to_user", userId, req.ScopeIds.Count.ToString());

            return ApiResult<MessageResponse>.Ok(new(true, $"Assigned {added} scope(s) to user."));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to assign scopes to user {UserId}", userId);
            return ApiResult<MessageResponse>.Fail("Internal error occurred while assigning scopes to user", 500);
        }   
    }

    /// <summary>
    /// Removes a specified scope from a user's active scopes.
    /// </summary>
    /// <remarks>This method deactivates the specified scope for the given user if it is currently active. If
    /// the scope is not assigned to the user or is already inactive, the method returns a failure result. The operation
    /// is logged for auditing purposes if an <paramref name="actorUserId"/> is provided.</remarks>
    /// <param name="userId">The unique identifier of the user from whom the scope will be removed. Cannot be null or whitespace.</param>
    /// <param name="scopeId">The unique identifier of the scope to be removed. Cannot be null or whitespace.</param>
    /// <param name="actorUserId">The unique identifier of the user performing the operation. Optional.</param>
    /// <param name="ip">The IP address of the actor performing the operation. Optional.</param>
    /// <param name="ua">The user agent string of the actor performing the operation. Optional.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success result if the scope was successfully removed, or a failure result with an
    /// appropriate message if the operation could not be completed.</returns>
    public static ApiResult<MessageResponse> RemoveScopeFromUser(
        string userId,
        string scopeId,
        AppConfig config)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(scopeId))
            return ApiResult<MessageResponse>.Fail("User ID and Scope ID are required", 400);

        try
        {
            var affected = ScopeStore.RemoveScopeFromUser(userId, scopeId);

            if (affected == 0)
                return ApiResult<MessageResponse>.Fail("Scope not assigned or already removed", 400);

            if (config.EnableAuditLogging) 
                Utils.Audit.Logg("remove_scope_from_user", scopeId, userId);

            return ApiResult<MessageResponse>.Ok(new(true, $"Removed scope '{scopeId}' from user '{userId}'."));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to remove scope {ScopeId} from user {UserId}", scopeId, userId);
            return ApiResult<MessageResponse>.Fail("Internal error occurred while removing scope from user", 500);
        }
    }

    /// <summary>
    /// Retrieves the total number of scopes currently stored.
    /// </summary>
    /// <returns>The total count of scopes as an integer. Returns 0 if no scopes are stored.</returns>
    public static int GetScopeCount() => ScopeStore.GetScopeCount();
}
