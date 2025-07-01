using System.Security.Cryptography;
using Serilog;
using static nebulae.dotArgon2.Argon2;

using madTypes.Api.Common;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using madTypes.Common;

using microauthd.Common;
using microauthd.Config;
using microauthd.Data;

namespace microauthd.Services;

public static class ClientService
{
    /// <summary>
    /// Attempts to create a new client with the specified request parameters and configuration.
    /// </summary>
    /// <remarks>The method validates the provided client ID and client secret before attempting to create the
    /// client.  If the client creation fails (e.g., due to a duplicate client ID), an error message is
    /// returned.</remarks>
    /// <param name="req">The request containing the client details, including <see cref="CreateClientRequest.ClientId"/> and <see
    /// cref="CreateClientRequest.ClientSecret"/>.</param>
    /// <param name="config">The application configuration used for hashing and other settings.</param>
    /// <param name="actorUserId">The optional ID of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ip">The optional IP address of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ua">The optional user agent string of the user performing the operation, used for auditing purposes.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/>.  If the client is successfully
    /// created, the result is successful and includes a message indicating the created client ID.  Otherwise, the
    /// result is a failure with an appropriate error message.</returns>
    public static ApiResult<ClientObject> CreateClient(
        CreateClientRequest req,
        AppConfig config)
    {
        if (!Utils.IsValidTokenName(req.ClientId))
            return ApiResult<ClientObject>.Fail("Invalid client_id", 400);

        if (string.IsNullOrWhiteSpace(req.ClientSecret))
            return ApiResult<ClientObject>.Fail("Client secret required", 400);

        if (string.IsNullOrWhiteSpace(req.Audience))
            return ApiResult<ClientObject>.Fail("Audience required", 400);

        try
        {
            var hash = AuthService.HashPassword(req.ClientSecret, config);

            var clientId = Guid.NewGuid().ToString();

            var clientObj = ClientStore.CreateClient(
                clientId,
                req.ClientId,
                hash,
                req.DisplayName ?? string.Empty,
                req.Audience
            );

            if (clientObj is null)
                return ApiResult<ClientObject>.Fail("Client creation failed (duplicate client_id?)", 400);

            if (config.EnableAuditLogging)
                    Utils.Audit.Logg("create_client", req.ClientId);

            return ApiResult<ClientObject>.Ok(clientObj);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error creating client with ID {ClientId}", req.ClientId);
            return ApiResult<ClientObject>.Fail("Internal error occurred while creating client.", 500);
        }
    }

    /// <summary>
    /// Updates the details of an existing client in the database.
    /// </summary>
    /// <remarks>The method performs several validations, including ensuring that the client identifier is
    /// non-empty, valid, and not already in use by another client. If the update is successful, the method retrieves
    /// and returns the updated client object. If the update fails or the client cannot be found, an error result is
    /// returned.</remarks>
    /// <param name="id">The unique identifier of the client to update.</param>
    /// <param name="updated">An object containing the updated client details. The <see cref="ClientObject.ClientId"/> property must be
    /// non-empty and valid.</param>
    /// <param name="config">The application configuration used for the operation.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the updated <see cref="ClientObject"/> if the operation succeeds;
    /// otherwise, an <see cref="ApiResult{T}"/> with an error message describing the failure.</returns>
    public static ApiResult<ClientObject> UpdateClient(
        string id,
        ClientObject updated,
        AppConfig config
    )
    {
        if (string.IsNullOrWhiteSpace(updated.ClientId))
            return ApiResult<ClientObject>.Fail("Client identifier is required.", 400);

        if (!Utils.IsValidTokenName(updated.ClientId))
            return ApiResult<ClientObject>.Fail("Client identifier is not valid.", 400);

        try
        {
            // Check for identifier conflicts
            var conflict = ClientStore.DoesClientIdExist(id, updated.ClientId);

            if (conflict)
                return ApiResult<ClientObject>.Fail("Another client already uses that identifier.", 400);

            var success = ClientStore.UpdateClient(id, updated);

            if (!success)
                return ApiResult<ClientObject>.Fail("Client update failed or client not found.", 400);

            // Invalidate cache for the client ID if it was updated
            if (!string.IsNullOrEmpty(updated.ClientId))
            {
                AuthService.InvalidateClientCache(updated.ClientId);
                Log.Debug("Client cache invalidated for client ID {ClientId}", updated.ClientId);
            }

            // Reload full object to return
            var client = ClientStore.GetClientObjById(id);

            return client is not null
                ? ApiResult<ClientObject>.Ok(client)
                : ApiResult<ClientObject>.Fail("Updated client could not be retrieved.", 400);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error updating client with ID {ClientId}", id);
            return ApiResult<ClientObject>.Fail("Internal error occurred while updating client.", 500);
        }
    }

    /// <summary>
    /// Retrieves a list of all active clients from the database.
    /// </summary>
    /// <remarks>This method queries the database for clients that are marked as active and returns them in
    /// ascending order of their client IDs. Each client is represented as a <see cref="ClientObject"/>
    /// object.</remarks>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="ClientObject"/> objects representing the active
    /// clients. If no active clients are found, the list will be empty.</returns>
    public static ApiResult<List<ClientObject>> GetAllClients()
    {
        try
        {
            var clients = ClientStore.ListAllClients();

            return ApiResult<List<ClientObject>>.Ok(clients);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error retrieving all clients");
            return ApiResult<List<ClientObject>>.Fail("Internal error occurred while retrieving clients.", 500);
        }
    }

    /// <summary>
    /// Retrieves a client by its unique identifier.
    /// </summary>
    /// <remarks>This method queries the database for a client with the specified identifier. If a matching
    /// client is found, it is returned as part of a successful <see cref="ApiResult{T}"/>. If no client is found, a
    /// "Not Found" result is returned.</remarks>
    /// <param name="id">The unique identifier of the client to retrieve. Cannot be null or empty.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the client object if found, or a "Not Found" result if no client exists
    /// with the specified identifier.</returns>
    public static ApiResult<ClientObject> GetClientById(string id)
    {
        try
        {
            var client = ClientStore.GetClientObjById(id);

            return client is null
                ? ApiResult<ClientObject>.NotFound($"Client '{id}' not found.")
                : ApiResult<ClientObject>.Ok(client);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error retrieving client with ID {ClientId}", id);
            return ApiResult<ClientObject>.Fail("Internal error occurred while retrieving client.", 500);
        }
    }

    /// <summary>
    /// Retrieves the client ID associated with the specified client identifier.
    /// </summary>
    /// <remarks>This method attempts to retrieve the client ID from the underlying client store. If the
    /// client identifier is invalid,  the method returns a failure result with a 400 status code. If the client is not
    /// found, a failure result with a 404 status code is returned.  In the event of an internal error, a failure result
    /// with a 500 status code is returned.</remarks>
    /// <param name="clientIdentifier">The unique identifier of the client. This parameter cannot be null, empty, or consist solely of whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the client ID if found, or an error message and status code if the
    /// client identifier is invalid,  the client is not found, or an internal error occurs.</returns>
    public static ApiResult<string> GetClientIdByIdentifier(string clientIdentifier)
    {
        if (string.IsNullOrWhiteSpace(clientIdentifier))
            return ApiResult<string>.Fail("Client identifier is required", 400);

        try
        {
            var id = ClientStore.GetClientIdByIdentifier(clientIdentifier);

            return id == null
                ? ApiResult<string>.Fail("Client not found", 404)
                : ApiResult<string>.Ok(id);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error retrieving client ID by identifier");
            return ApiResult<string>.Fail("Internal error occurred", 500);
        }
    }

    /// <summary>
    /// Deletes a client record from the database based on the specified client ID.
    /// </summary>
    /// <remarks>This method attempts to delete a client record from the database. If the deletion fails
    /// (e.g., due to a database error or if the client ID does not exist), the method returns a failure result.
    /// Additionally, an audit log entry is created for successful deletions, including optional metadata such as the
    /// actor's user ID, IP address, and user agent.</remarks>
    /// <param name="clientIdent">The unique identifier of the client to delete. Cannot be null or empty.</param>
    /// <param name="config">The application configuration used for logging and auditing. Cannot be null.</param>
    /// <param name="actorUserId">The ID of the user performing the operation, used for auditing. Optional.</param>
    /// <param name="ip">The IP address of the user performing the operation, used for auditing. Optional.</param>
    /// <param name="ua">The user agent string of the user performing the operation, used for auditing. Optional.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success result if the client was deleted successfully; otherwise, returns a failure result
    /// with an error message.</returns>
    public static ApiResult<MessageResponse> DeleteClient(
        string clientIdent,
        AppConfig config)
    {
        try
        {
            // Revoke sessions
            ClientStore.RevokeClientSessions(clientIdent);

            // Revoke refresh tokens
            ClientStore.RevokeClientRefreshTokens(clientIdent);

            // Delete client scopes
            ClientStore.DeleteClientScopes(clientIdent);

            // Finally delete the client
            var deleted = ClientStore.DeleteClientByClientIdentifier(clientIdent);

            if (!deleted)
                return ApiResult<MessageResponse>.Fail("Failed to delete client", 400);

            if (config.EnableAuditLogging) 
                Utils.Audit.Logg("delete_client", clientIdent);

            return ApiResult<MessageResponse>.Ok(new(true, $"Client '{clientIdent}' deleted"));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error deleting client with ID {ClientId}", clientIdent);
            return ApiResult<MessageResponse>.Fail("Internal error occurred while deleting client.", 500);
        }
    }

    /// <summary>
    /// Regenerates the client secret for the specified client ID and returns the new secret.
    /// </summary>
    /// <remarks>This method generates a new client secret, hashes it using the provided application
    /// configuration, and updates the client record in the data store. The new secret is returned in plain text only
    /// once as part of the response. Audit logging is performed to record the action.</remarks>
    /// <param name="id">The unique identifier of the client whose secret is being regenerated. Cannot be null or empty.</param>
    /// <param name="config">The application configuration used for hashing the secret. Must not be null.</param>
    /// <param name="actorUserId">The identifier of the user performing the operation. Used for audit logging. Cannot be null or empty.</param>
    /// <param name="ip">The IP address of the user performing the operation. Optional; can be null.</param>
    /// <param name="ua">The user agent string of the user performing the operation. Optional; can be null.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> with the new client secret in plain
    /// text. The response indicates success or failure, along with an HTTP status code.</returns>
    public static ApiResult<MessageResponse> RegenerateClientSecret(
            string id,
            AppConfig config)
    {
        if (string.IsNullOrWhiteSpace(id))
            return ApiResult<MessageResponse>.Fail("Client ID is required.", 400);

        var newSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var hash = AuthService.HashPassword(newSecret, config);

        var success = ClientStore.UpdateClientSecret(id, hash);
        if (!success)
            return ApiResult<MessageResponse>.Fail("Failed to update client secret.", 500);

        // Invalidate cache for the client Identifier associated with this ID
        AuthService.InvalidateClientCache(ClientStore.GetClientIdentifierById(id)!);
        Log.Debug("Client cache invalidated for client ID {ClientId}", id);

        if (config.EnableAuditLogging)
            Utils.Audit.Logg(
                action: "client.secret.regenerated",
                target: $"clientId"
            );

        // IMPORTANT: Return the plain secret only once
        return ApiResult<MessageResponse>.Ok(
            new MessageResponse(true, newSecret),
            200
        );
    }

    /// <summary>
    /// Updates the secret for a specified client and returns the result of the operation.
    /// </summary>
    /// <remarks>This method retrieves the client by its ID and verifies that it is active. If the client is
    /// not found or inactive, the operation fails with a 404 error. If <paramref name="req.NewSecret"/> is null or
    /// whitespace, a new secret is generated using the application's authentication service. The secret is hashed
    /// before being updated in the client store.</remarks>
    /// <param name="req">The request containing the client ID and the new secret. If <paramref name="req.NewSecret"/> is null or
    /// whitespace, a new secret will be generated automatically.</param>
    /// <param name="config">The application configuration used for hashing the secret.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/>. If the operation succeeds, the
    /// response includes the new secret. If the client is not found or inactive, or if the update fails, the response
    /// contains an error message.</returns>
    public static ApiResult<MessageResponse> ChangeClientSecret(ChangeClientSecretRequest req, AppConfig config)
    {
        var client = ClientStore.GetClientById(req.ClientId);
        if (client == null || !client.IsActive)
            return ApiResult<MessageResponse>.Fail("Client not found", 404);

        var newSecret = string.IsNullOrWhiteSpace(req.NewSecret)
            ? AuthService.GeneratePassword(32)
            : req.NewSecret.Trim();

        var hash = AuthService.HashPassword(newSecret, config);

        if (!ClientStore.UpdateClientSecret(client.Id, hash))
            return ApiResult<MessageResponse>.Fail("Failed to update client secret", 400);

        AuthService.InvalidateClientCache(client.ClientId);

        return ApiResult<MessageResponse>.Ok(new MessageResponse(true, newSecret));
    }

    /// <summary>
    /// Replaces the scopes assigned to a client with the specified set of scopes.
    /// </summary>
    /// <remarks>This method updates the scopes assigned to a client by comparing the current scopes with the
    /// provided scopes. Scopes that are not currently assigned but are included in the provided set will be added, and
    /// scopes that are currently assigned but are not included in the provided set will be removed.</remarks>
    /// <param name="dto">The scope assignment details, including the target client ID and the list of scopes to assign.</param>
    /// <param name="config">The application configuration used for scope assignment operations.</param>
    /// <param name="actorUserId">The ID of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ip">The IP address of the user performing the operation, used for auditing purposes. Can be <see langword="null"/>.</param>
    /// <param name="ua">The user agent string of the user performing the operation, used for auditing purposes. Can be <see
    /// langword="null"/>.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates whether the operation
    /// was successful. If successful, the response contains a success message; otherwise, it contains an error message.</returns>
    public static ApiResult<MessageResponse> ReplaceClientScopes(
            ScopeAssignmentDto dto,
            AppConfig config,
            string actorUserId,
            string? ip,
            string? ua)
    {
        if (string.IsNullOrWhiteSpace(dto.TargetId))
            return ApiResult<MessageResponse>.Fail("Missing targetId", 400);

        var current = ScopeStore.GetAssignedScopesForClient(dto.TargetId)
            .Select(r => r.Id)
            .ToHashSet();

        var submitted = dto.Scopes
            .Where(r => !string.IsNullOrWhiteSpace(r.Id))
            .Select(r => r.Id)
            .ToHashSet();

        var toAdd = submitted.Except(current).ToList();
        var toRemove = current.Except(submitted).ToList();

        // AddScopesToClient and RemoveScopeFromClient are both audit logged internally,
        // so we don't need to log here again as it's redundant.
        AssignScopesRequest req = new();
        req.ScopeIds.AddRange(toAdd);
        ScopeService.AddScopesToClient(dto.TargetId, req, config);

        foreach (var scopeId in toRemove)
            ScopeService.RemoveScopeFromClient(dto.TargetId, scopeId, config);

        return ApiResult<MessageResponse>.Ok(new MessageResponse(true, "Scopes updated."));
    }

    /// <summary>
    /// Adds a redirect URI to the specified client.
    /// </summary>
    /// <remarks>This method attempts to add the specified redirect URI to the client identified by <paramref
    /// name="clientId"/>. If the operation fails due to an internal error, a status code of 500 is returned.</remarks>
    /// <param name="clientId">The unique identifier of the client to which the redirect URI will be added. Cannot be null, empty, or
    /// whitespace.</param>
    /// <param name="redirectUri">The redirect URI to associate with the client. Must be a valid URI and cannot be null, empty, or whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the result of the operation.  If successful, the result includes the
    /// added <see cref="ClientRedirectUriObject"/> and a status code of 201. If the operation fails, the result
    /// includes an error message and an appropriate status code.</returns>
    public static ApiResult<ClientRedirectUriObject> AddRedirectUri(string clientId, string redirectUri)
    {
        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(redirectUri))
            return ApiResult<ClientRedirectUriObject>.Fail("Client ID and redirect URI are required", 400);

        try
        {
            var result = ClientStore.InsertRedirectUri(clientId, redirectUri);
            return result is not null
                ? ApiResult<ClientRedirectUriObject>.Ok(result, 201)
                : ApiResult<ClientRedirectUriObject>.Fail("Failed to add redirect URI", 400);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error adding redirect URI for client {ClientId}", clientId);
            return ApiResult<ClientRedirectUriObject>.Fail("Internal server error", 500);
        }
    }

    /// <summary>
    /// Retrieves the list of redirect URIs associated with the specified client.
    /// </summary>
    /// <remarks>This method attempts to retrieve redirect URIs from the underlying client store. If the
    /// client ID is invalid or an error occurs during retrieval, the method returns a failure result with an error
    /// message and status code.</remarks>
    /// <param name="clientId">The unique identifier of the client for which redirect URIs are being retrieved. Must not be null, empty, or
    /// consist solely of whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="ClientRedirectUriObject"/> instances representing
    /// the redirect URIs for the specified client. If the operation fails, the result will include an error message and
    /// an appropriate HTTP status code.</returns>
    public static ApiResult<List<ClientRedirectUriObject>> GetRedirectUrisForClient(string clientId)
    {
        if (string.IsNullOrWhiteSpace(clientId))
            return ApiResult<List<ClientRedirectUriObject>>.Fail("Client ID is required", 400);

        try
        {
            var uris = ClientStore.GetRedirectUrisByClientId(clientId);
            return ApiResult<List<ClientRedirectUriObject>>.Ok(uris);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to list redirect URIs for client {ClientId}", clientId);
            return ApiResult<List<ClientRedirectUriObject>>.Fail("Failed to list redirect URIs", 500);
        }
    }

    /// <summary>
    /// Deletes a redirect URI identified by the specified ID.
    /// </summary>
    /// <remarks>This method attempts to delete a redirect URI from the underlying store. If the specified ID
    /// does not exist,  the method returns a "not found" result. In case of an unexpected error, the method logs the
    /// exception and  returns a failure result.</remarks>
    /// <param name="id">The unique identifier of the redirect URI to delete. This parameter cannot be null, empty, or consist solely of
    /// whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. If the redirect URI is successfully deleted, the response contains a success message. If the redirect
    /// URI is not found, the response indicates a "not found" status. If an error occurs during the operation, the
    /// response contains an error message and a status code of 500.</returns>
    public static ApiResult<MessageResponse> DeleteRedirectUri(string id)
    {
        if (string.IsNullOrWhiteSpace(id))
            return ApiResult<MessageResponse>.Fail("Redirect URI ID is required", 400);

        try
        {
            var ok = ClientStore.DeleteRedirectUriById(id);
            return ok
                ? ApiResult<MessageResponse>.Ok(new MessageResponse(true, "Redirect URI deleted"))
                : ApiResult<MessageResponse>.NotFound("Redirect URI not found");
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to delete redirect URI {Id}", id);
            return ApiResult<MessageResponse>.Fail("Failed to delete redirect URI", 500);
        }
    }

    /// <summary>
    /// Retrieves the total number of clients currently stored in the system.
    /// </summary>
    /// <returns>The total count of clients as an integer. Returns 0 if no clients are stored.</returns>
    public static int GetClientCount() => ClientStore.GetClientCount();
}        
