using mad.Common;
using mad.Http;
using madTypes.Api.Common;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using System.CommandLine;
using System.Text.Json;

namespace mad.Commands;

internal static class ClientCommands
{
    public static Command Build()
    {
        var cmd = new Command("client", "Manage OIDC clients");

        cmd.AddCommand(CreateClientCommand());
        cmd.AddCommand(UpdateClientCommand());
        cmd.AddCommand(ChangeClientSecretCommand());
        cmd.AddCommand(ListClientsCommand());
        cmd.AddCommand(GetClientByIdCommand());
        cmd.AddCommand(DeleteClientCommand());

        cmd.AddCommand(AddRedirectUriCommand());
        cmd.AddCommand(ListRedirectUrisCommand());
        cmd.AddCommand(DeleteRedirectUriCommand());

        cmd.AddCommand(SetFeatureFlagCommand());
        cmd.AddCommand(GetFeatureFlagCommand());
        cmd.AddCommand(SetFlagOptionsCommand());
        cmd.AddCommand(GetFlagOptionsCommand());

        cmd.AddCommand(AddExternalIdpCommand());
        cmd.AddCommand(UpdateExternalIdpCommand());
        cmd.AddCommand(ListExternalIdpsCommand());
        cmd.AddCommand(DeleteExternalIdpCommand());

        cmd.AddCommand(AssignScopesCommand());
        cmd.AddCommand(ListScopesCommand());
        cmd.AddCommand(RemoveScopeCommand());

        return cmd;
    }

    private static Command CreateClientCommand()
    {
        var cmd = new Command("create", "Create a new OIDC client");

        var clientId = new Option<string>("--client-id") { IsRequired = true };
        var secret = new Option<string?>("--secret", "Client secret to use (omit to auto-generate)");
        var genLen = new Option<int?>("--gen-password", "Generate a random secret of the given length");
        var name = new Option<string?>("--display-name", () => string.Empty);
        var audience = new Option<string?>("--audience", "Audience for the client (optional. Defaults to 'microauthd'") { IsRequired = false };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(clientId);
        cmd.AddOption(secret);
        cmd.AddOption(genLen);
        cmd.AddOption(name);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(audience);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string id, string? s, int? gen, string? disp, string? aud, bool jsonOut) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var error = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    if (jsonOut)
                        Console.WriteLine(JsonSerializer.Serialize(error, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(error.Message);
                    return;
                }

                var actualSecret = s;

                if (gen.HasValue)
                {
                    actualSecret = AuthUtils.GeneratePassword(gen.Value);
                    if (!jsonOut)
                        Console.WriteLine($"Generated client secret: {actualSecret}");
                }

                if (string.IsNullOrWhiteSpace(actualSecret))
                {
                    var error = new ErrorResponse(false, "Client secret is required (use --secret or --gen-password).");
                    if (jsonOut)
                        Console.WriteLine(JsonSerializer.Serialize(error, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(error.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var result = await client.CreateClient(new CreateClientRequest
                {
                    ClientId = id,
                    ClientSecret = actualSecret,
                    DisplayName = disp,
                    Audience = aud ?? "microauthd"
                });

                if (result is null)
                {
                    var error = new ErrorResponse(false, "Client creation failed.");
                    if (jsonOut)
                        Console.WriteLine(JsonSerializer.Serialize(error, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(error.Message);
                    return;
                }

                if (jsonOut)
                {
                    Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.ClientObject));
                }
                else
                {
                    Console.WriteLine($"Created client {id} with ID: {result.Id}");
                }
            }
            catch (Exception ex)
            {
                var error = new ErrorResponse(false, $"Unhandled exception: {ex.Message}");
                if (jsonOut)
                    Console.WriteLine(JsonSerializer.Serialize(error, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine("Error creating client.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, adminToken, clientId, secret, genLen, name, audience, jsonOut);

        return cmd;
    }

    private static Command UpdateClientCommand()
    {
        var cmd = new Command("update", "Update a client");

        var id = new Option<string>("--id") { IsRequired = true };
        var clientId = new Option<string?>("--client-id", "New client identifier");
        var displayName = new Option<string?>("--display-name", "New display name");
        var active = new Option<bool?>("--is-active", "Set active status (true/false)");
        var audience = new Option<string?>("--audience", "New audience for the client (optional, defaults to 'microauthd')");

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(id);
        cmd.AddOption(clientId);
        cmd.AddOption(displayName);
        cmd.AddOption(active);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);
        cmd.AddOption(audience);

        cmd.SetHandler(async (
            string url, string? token, string id,
            string? newClientId, string? newName, bool? newStatus, string? aud, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                if (newClientId is null && newName is null && newStatus is null && audience is null)
                {
                    var err = new ErrorResponse(false, "You must provide at least one field to update.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var client = new MadApiClient(url, token);
                var existing = await client.GetClientById(id);
                if (existing is null)
                {
                    var err = new ErrorResponse(false, $"Client '{id}' not found.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var updatedInput = new ClientObject
                {
                    Id = existing.Id,
                    ClientId = newClientId ?? existing.ClientId,
                    DisplayName = newName ?? existing.DisplayName,
                    IsActive = newStatus ?? existing.IsActive,
                    CreatedAt = existing.CreatedAt,
                    Audience = aud ?? existing.Audience
                };

                var updated = await client.UpdateClient(id, updatedInput);
                if (updated is null)
                {
                    var err = new ErrorResponse(false, "Update failed.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(updated, MadJsonContext.Default.ClientObject));
                }
                else
                {
                    Console.WriteLine($"Client updated: {updated.ClientId}");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Unexpected error: {ex.Message}");
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
            }
        }, adminUrl, adminToken, id, clientId, displayName, active, audience, jsonOut);

        return cmd;
    }

    private static Command ListClientsCommand()
    {
        var cmd = new Command("list", "List all active clients");
        
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(jsonOut);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var error = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(error, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(error.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var clients = await client.ListClients();

                if (clients is null || clients.Count == 0)
                {
                    if (json)
                        Console.WriteLine("[]");
                    else
                        Console.WriteLine("(no clients)");
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(clients, MadJsonContext.Default.ListClientObject));
                }
                else
                {
                    Console.WriteLine($"{"Id",-36}  {"Client Identifier",-24}  {"Active",-8}  Display Name");
                    Console.WriteLine(new string('-', 100));
                    foreach (var c in clients)
                    {
                        Console.WriteLine($"{c.Id,-36}  {c.ClientId,-24}  {c.IsActive,-8}  {c.DisplayName}");
                    }
                }
            }
            catch (Exception ex)
            {
                var error = new ErrorResponse(false, $"Exception while listing clients: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(error, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine("Failed to retrieve client list.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, adminToken, jsonOut);

        return cmd;
    }

    private static Command GetClientByIdCommand()
    {
        var cmd = new Command("get", "Get client by ID");

        var id = new Option<string>("--id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(id);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string id, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var client = new MadApiClient(url, token);
                var obj = await client.GetClientById(id);

                if (obj is null)
                {
                    var err = new ErrorResponse(false, $"Client '{id}' not found.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(obj, MadJsonContext.Default.ClientObject));
                }
                else
                {
                    Console.WriteLine($"Id:           {obj.Id}");
                    Console.WriteLine($"ClientId:     {obj.ClientId}");
                    Console.WriteLine($"Display Name: {obj.DisplayName}");
                    Console.WriteLine($"Active:       {obj.IsActive}");
                    Console.WriteLine($"Created At:   {obj.CreatedAt}");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Unexpected error: {ex.Message}");
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
            }
        }, adminUrl, adminToken, id, jsonOut);

        return cmd;
    }

    private static Command ChangeClientSecretCommand()
    {
        var cmd = new Command("change-secret", "Regenerate or set a new client secret");

        var clientId = new Option<string>("--id") { IsRequired = true };
        var newSecret = new Option<string?>("--secret", "Optional custom secret");
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(clientId);
        cmd.AddOption(newSecret);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (
            string id,
            string? secret,
            string url,
            string? token,
            bool json) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                var err = new ErrorResponse(false, "No token. Use --admin-token or `mad session login`.");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                    Console.Error.WriteLine(err.Message);
                return;
            }

            var client = new MadApiClient(url, token);
            var response = await client.ChangeClientSecret(new ChangeClientSecretRequest(id, secret));

            if (response is null)
            {
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(new ErrorResponse(false, "Secret change failed"), MadJsonContext.Default.ErrorResponse));
                else
                    Console.Error.WriteLine("Failed to change client secret.");
                return;
            }

            if (json)
            {
                Console.WriteLine(JsonSerializer.Serialize(response, MadJsonContext.Default.MessageResponse));
            }
            else
            {
                Console.WriteLine("Client secret changed successfully.");
                Console.WriteLine("Secret (please store it now):");
                Console.WriteLine($"\n  {response.Message}\n");
            }
        }, clientId, newSecret, adminUrl, adminToken, jsonOut);

        return cmd;
    }

    private static Command DeleteClientCommand()
    {
        var cmd = new Command("delete", "Delete a client");

        var id = new Option<string>("--id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(id);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string id, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.DeleteClient(id);

                if (ok)
                {
                    var msg = new MessageResponse(true, $"Deleted client id {id}");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(msg, MadJsonContext.Default.MessageResponse));
                    else
                        Console.WriteLine(msg.Message);
                }
                else
                {
                    var err = new ErrorResponse(false, $"Failed to delete client id {id}");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Exception deleting client id {id}: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine($"Error deleting client id {id}.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, adminToken, id, jsonOut);

        return cmd;
    }

    private static Command AddRedirectUriCommand()
    {
        var cmd = new Command("add-redirect-uri", "Add a valid redirect URI to a client");

        var clientGuid = new Option<string>("--id", "GUID of the client") { IsRequired = true };
        var redirectUri = new Option<string>("--uri", "Redirect URI to allow") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(clientGuid);
        cmd.AddOption(redirectUri);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string id, string uri, bool json) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                return;
            }

            var client = new MadApiClient(url, token);
            var created = await client.AddRedirectUri(id, uri); // id is GUID here

            if (created == null)
            {
                var err = new ErrorResponse(false, "Failed to add redirect URI.");
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                return;
            }

            if (json)
            {
                Console.WriteLine(JsonSerializer.Serialize(created, MadJsonContext.Default.ClientRedirectUriObject));
            }
            else
            {
                Console.WriteLine($"Added redirect URI '{created.RedirectUri}' to client {id}");
            }
        }, adminUrl, adminToken, clientGuid, redirectUri, jsonOut);

        return cmd;
    }

    private static Command ListRedirectUrisCommand()
    {
        var cmd = new Command("list-redirect-uris", "List redirect URIs for a client");

        var clientId = new Option<string>("--client-id", "The GUID of the client") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(clientId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string cid, bool json) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                return;
            }

            var client = new MadApiClient(url, token);
            var list = await client.ListRedirectUris(cid);

            if (list.Count == 0)
            {
                Console.WriteLine(json ? "[]" : "(no redirect URIs)");
                return;
            }

            if (json)
            {
                Console.WriteLine(JsonSerializer.Serialize(list, MadJsonContext.Default.ListClientRedirectUriObject));
            }
            else
            {
                Console.WriteLine($"{"Id",-36}  {"Redirect URI"}");
                Console.WriteLine(new string('-', 80));
                foreach (var uri in list)
                    Console.WriteLine($"{uri.Id,-36}  {uri.RedirectUri}");
            }
        }, adminUrl, adminToken, clientId, jsonOut);

        return cmd;
    }

    private static Command DeleteRedirectUriCommand()
    {
        var cmd = new Command("delete-redirect-uri", "Delete a redirect URI by its ID");

        var uriId = new Option<string>("--id", "The ID of the redirect URI to delete") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(uriId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string id, bool json) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                return;
            }

            var client = new MadApiClient(url, token);
            var ok = await client.DeleteRedirectUri(id);

            if (ok)
            {
                var msg = new MessageResponse(true, $"Redirect URI {id} deleted.");
                Console.WriteLine(json
                    ? JsonSerializer.Serialize(msg, MadJsonContext.Default.MessageResponse)
                    : msg.Message);
            }
            else
            {
                var err = new ErrorResponse(false, $"Failed to delete redirect URI {id}.");
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
            }
        }, adminUrl, adminToken, uriId, jsonOut);

        return cmd;
    }

    private static Command SetFeatureFlagCommand()
    {
        var cmd = new Command("set-flag", "Enable or disable a feature flag for a client");

        var clientId = new Option<string>("--client-id") { IsRequired = true };
        var flag = new Option<string>("--flag", "Feature flag name (e.g. ENABLE_TOTP)") { IsRequired = true };
        var isEnabled = new Option<bool>("--enable", "Enable or disable the flag") { IsRequired = true };

        var url = SharedOptions.AdminUrl;
        var token = SharedOptions.AdminToken;
        var json = SharedOptions.OutputJson;

        cmd.AddOption(clientId);
        cmd.AddOption(flag);
        cmd.AddOption(isEnabled);
        cmd.AddOption(url);
        cmd.AddOption(token);
        cmd.AddOption(json);

        cmd.SetHandler(async (string baseUrl, string? authToken, string client, string flag, bool enable, bool jsonOut) =>
        {
            try
            {
                authToken ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(authToken))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var clientApi = new MadApiClient(baseUrl, authToken);
                var response = await clientApi.SetClientFeatureFlag(client, flag, enable);

                if (response is false)
                {
                    Console.WriteLine(JsonSerializer.Serialize(new ErrorResponse(false, "Failed to set feature flag"), MadJsonContext.Default.ErrorResponse));
                }
                else if (jsonOut)
                {
                    Console.WriteLine(JsonSerializer.Serialize(response, MadJsonContext.Default.MessageResponse));
                }
                else
                {
                    Console.WriteLine($"The response was {response}");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, ex.Message);
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
            }
        }, url, token, clientId, flag, isEnabled, json);

        return cmd;
    }

    private static Command GetFeatureFlagCommand()
    {
        var cmd = new Command("get-flag", "Check if a feature flag is enabled for a client");

        var clientId = new Option<string>("--client-id") { IsRequired = true };
        var flag = new Option<string>("--flag") { IsRequired = true };

        var url = SharedOptions.AdminUrl;
        var token = SharedOptions.AdminToken;
        var json = SharedOptions.OutputJson;

        cmd.AddOption(clientId);
        cmd.AddOption(flag);
        cmd.AddOption(url);
        cmd.AddOption(token);
        cmd.AddOption(json);

        cmd.SetHandler(async (string baseUrl, string? authToken, string client, string flag, bool jsonOut) =>
        {
            try
            {
                authToken ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(authToken))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var clientApi = new MadApiClient(baseUrl, authToken);
                var enabled = await clientApi.GetClientFeatureFlag(client, flag);

                if (jsonOut)
                    Console.WriteLine(JsonSerializer.Serialize(enabled));
                else
                    Console.WriteLine((enabled is null or false) ? "disabled" : "enabled");
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, ex.Message);
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
            }
        }, url, token, clientId, flag, json);

        return cmd;
    }

    private static Command SetFlagOptionsCommand()
    {
        var cmd = new Command("set-flag-options", "Set the extended options string for a feature flag");

        var clientId = new Option<string>("--client-id") { IsRequired = true };
        var flag = new Option<string>("--flag") { IsRequired = true };
        var options = new Option<string>("--options") { IsRequired = true };

        var url = SharedOptions.AdminUrl;
        var token = SharedOptions.AdminToken;
        var json = SharedOptions.OutputJson;

        cmd.AddOption(clientId);
        cmd.AddOption(flag);
        cmd.AddOption(options);
        cmd.AddOption(url);
        cmd.AddOption(token);
        cmd.AddOption(json);

        cmd.SetHandler(async (string baseUrl, string? authToken, string client, string flag, string opt, bool jsonOut) =>
        {
            try
            {
                authToken ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(authToken))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var clientApi = new MadApiClient(baseUrl, authToken);
                var response = await clientApi.SetClientFeatureOption(client, flag, opt);

                if (jsonOut)
                    Console.WriteLine(JsonSerializer.Serialize(response, MadJsonContext.Default.MessageResponse));
                else
                    Console.WriteLine($"Updated result is {response}");
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, ex.Message);
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
            }
        }, url, token, clientId, flag, options, json);

        return cmd;
    }

    private static Command GetFlagOptionsCommand()
    {
        var cmd = new Command("get-flag-options", "Retrieve the extended options string for a flag");

        var clientId = new Option<string>("--client-id") { IsRequired = true };
        var flag = new Option<string>("--flag") { IsRequired = true };

        var url = SharedOptions.AdminUrl;
        var token = SharedOptions.AdminToken;
        var json = SharedOptions.OutputJson;

        cmd.AddOption(clientId);
        cmd.AddOption(flag);
        cmd.AddOption(url);
        cmd.AddOption(token);
        cmd.AddOption(json);

        cmd.SetHandler(async (string baseUrl, string? authToken, string client, string flag, bool jsonOut) =>
        {
            try
            {
                authToken ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(authToken))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var clientApi = new MadApiClient(baseUrl, authToken);
                var val = await clientApi.GetClientFeatureOption(client, flag);

                if (jsonOut)
                    Console.WriteLine(JsonSerializer.Serialize(val));
                else
                    Console.WriteLine(val ?? "(none)");
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, ex.Message);
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
            }
        }, url, token, clientId, flag, json);

        return cmd;
    }

    private static Command AddExternalIdpCommand()
    {
        var cmd = new Command("add-idp", "Add an external identity provider to a client");

        var clientGuid = new Option<string>("--id", "The GUID of the client") { IsRequired = true };
        var providerKey = new Option<string>("--provider-key", "Unique key for this provider") { IsRequired = true };
        var displayName = new Option<string>("--display-name", "Human-readable name") { IsRequired = true };
        var issuer = new Option<string>("--issuer", "OIDC issuer URL") { IsRequired = true };
        var externalClientId = new Option<string>("--external-client-id", "Client ID used at the external IdP") { IsRequired = true };
        var scopes = new Option<string>("--scopes", () => "openid email profile", "Scopes to request");

        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(clientGuid);
        cmd.AddOption(providerKey);
        cmd.AddOption(displayName);
        cmd.AddOption(issuer);
        cmd.AddOption(externalClientId);
        cmd.AddOption(scopes);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (
            string clientGuid,
            string providerKey,
            string displayName,
            string issuer,
            string externalClientId,
            string scopes,
            bool json) =>
        {
            var token = AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.WriteLine(JsonSerializer.Serialize(new ErrorResponse(false, "No token. Use `mad session login`."), MadJsonContext.Default.ErrorResponse));
                return;
            }

            var url = AuthUtils.TryLoadAdminUrl();
            var client = new MadApiClient(url, token);
            var localClient = await client.GetClientById(clientGuid);
            if (localClient == null)
            {
                Console.WriteLine(JsonSerializer.Serialize(new ErrorResponse(false, $"Client '{clientGuid}' not found"), MadJsonContext.Default.ErrorResponse));
                return;
            }

            var dto = new ExternalIdpProviderDto
            {
                ClientId = localClient.ClientId,
                ProviderKey = providerKey.Trim().ToLowerInvariant(),
                DisplayName = displayName.Trim(),
                Issuer = issuer.Trim(),
                ClientIdentifier = externalClientId.Trim(),
                Scopes = scopes.Trim()
            };

            var result = await client.AddExternalIdp(dto);
            if (result == null)
            {
                Console.WriteLine(JsonSerializer.Serialize(new ErrorResponse(false, "Failed to create external IdP."), MadJsonContext.Default.ErrorResponse));
                return;
            }

            if (json)
            {
                Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.ExternalIdpProviderDto));
            }
            else
            {
                Console.WriteLine($"External IdP '{result.ProviderKey}' added to client '{result.ClientId}'.");
            }
        },
        clientGuid, providerKey, displayName, issuer, externalClientId, scopes, jsonOut);

        return cmd;
    }

    private static Command UpdateExternalIdpCommand()
    {
        var cmd = new Command("update-idp", "Update an external identity provider");

        var clientGuid = new Option<string>("--id", "GUID of the client") { IsRequired = true };
        var idpId = new Option<string>("--idp-id", "ID of the external IdP to update") { IsRequired = true };
        var providerKey = new Option<string>("--provider-key") { IsRequired = true };
        var displayName = new Option<string>("--display-name") { IsRequired = true };
        var issuer = new Option<string>("--issuer") { IsRequired = true };
        var externalClientId = new Option<string>("--external-client-id") { IsRequired = true };
        var scopes = new Option<string>("--scopes", () => "openid email profile");

        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(clientGuid);
        cmd.AddOption(idpId);
        cmd.AddOption(providerKey);
        cmd.AddOption(displayName);
        cmd.AddOption(issuer);
        cmd.AddOption(externalClientId);
        cmd.AddOption(scopes);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (
            string clientGuid,
            string idpId,
            string providerKey,
            string displayName,
            string issuer,
            string externalClientId,
            string scopes,
            bool json) =>
        {
            var token = AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.WriteLine(JsonSerializer.Serialize(new ErrorResponse(false, "No token. Use `mad session login`."), MadJsonContext.Default.ErrorResponse));
                return;
            }

            var url = AuthUtils.TryLoadAdminUrl();
            var client = new MadApiClient(url, token);

            var dto = new ExternalIdpProviderDto
            {
                Id = idpId,
                ClientId = clientGuid,
                ProviderKey = providerKey.Trim().ToLowerInvariant(),
                DisplayName = displayName.Trim(),
                Issuer = issuer.Trim(),
                ClientIdentifier = externalClientId.Trim(),
                Scopes = scopes.Trim()
            };

            var result = await client.UpdateExternalIdp(dto);

            if (result is null)
            {
                Console.WriteLine(JsonSerializer.Serialize(new ErrorResponse(false, "Failed to update external IdP"), MadJsonContext.Default.ErrorResponse));
                return;
            }

            if (json)
                Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.ExternalIdpProviderDto));
            else
                Console.WriteLine($"External IdP '{result.ProviderKey}' updated.");
        },
        clientGuid, idpId, providerKey, displayName, issuer, externalClientId, scopes, jsonOut);

        return cmd;
    }

    private static Command ListExternalIdpsCommand()
    {
        var cmd = new Command("list-idps", "List external identity providers for a client");

        var clientGuid = new Option<string>("--id", "GUID of the client") { IsRequired = true };
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(clientGuid);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string clientGuid, bool json) =>
        {
            var token = AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.WriteLine(JsonSerializer.Serialize(new ErrorResponse(false, "No token. Use `mad session login`."), MadJsonContext.Default.ErrorResponse));
                return;
            }

            var url = AuthUtils.TryLoadAdminUrl();
            var client = new MadApiClient(url, token);
            var idps = await client.ListExternalIdps(clientGuid);

            if (idps == null || idps.Count == 0)
            {
                Console.WriteLine(json ? "[]" : "(no external providers)");
                return;
            }

            if (json)
            {
                Console.WriteLine(JsonSerializer.Serialize(idps, MadJsonContext.Default.ListExternalIdpProviderDto));
            }
            else
            {
                Console.WriteLine($"{"Id",-36} {"ProviderKey",-15} {"DisplayName",-25} Issuer");
                Console.WriteLine(new string('-', 100));
                foreach (var idp in idps)
                {
                    Console.WriteLine($"{idp.Id,-36} {idp.ProviderKey,-15} {idp.DisplayName,-25} {idp.Issuer}");
                }
            }
        }, clientGuid, jsonOut);

        return cmd;
    }

    private static Command DeleteExternalIdpCommand()
    {
        var cmd = new Command("delete-idp", "Delete an external identity provider");

        var clientGuid = new Option<string>("--id", "GUID of the client") { IsRequired = true };
        var idpId = new Option<string>("--idp-id", "ID of the external IdP to delete") { IsRequired = true };
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(clientGuid);
        cmd.AddOption(idpId);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string clientGuid, string idpId, bool json) =>
        {
            var token = AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.WriteLine(JsonSerializer.Serialize(new ErrorResponse(false, "No token. Use `mad session login`."), MadJsonContext.Default.ErrorResponse));
                return;
            }

            var url = AuthUtils.TryLoadAdminUrl();
            var client = new MadApiClient(url, token);
            var ok = await client.DeleteExternalIdp(idpId, clientGuid);

            if (!ok)
            {
                Console.WriteLine(JsonSerializer.Serialize(new ErrorResponse(false, "Failed to delete external IdP."), MadJsonContext.Default.ErrorResponse));
                return;
            }

            if (json)
            {
                var response = new MessageResponse(true, "External IdP deleted");
                Console.WriteLine(JsonSerializer.Serialize(response, MadJsonContext.Default.MessageResponse));
            }
            else
            {
                Console.WriteLine("External IdP deleted.");
            }
        }, clientGuid, idpId, jsonOut);

        return cmd;
    }

    private static Command AssignScopesCommand()
    {
        var cmd = new Command("assign-scope", "Assign scopes to a client");

        var clientId = new Option<string>("--client-id") { IsRequired = true };
        var scopeIds = new Option<List<string>>("--scope-id")
        {
            IsRequired = true,
            AllowMultipleArgumentsPerToken = true
        };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(clientId);
        cmd.AddOption(scopeIds);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string cid, List<string> sids, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.AssignScopesToClient(cid, sids);

                if (ok)
                {
                    var msg = new MessageResponse(true, "Scopes assigned.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(msg, MadJsonContext.Default.MessageResponse));
                    else
                        Console.WriteLine(msg.Message);
                }
                else
                {
                    var err = new ErrorResponse(false, "Failed to assign scopes.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Exception while assigning scopes: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine("Error assigning scopes to client.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, adminToken, clientId, scopeIds, jsonOut);

        return cmd;
    }

    private static Command ListScopesCommand()
    {
        var cmd = new Command("list-scopes", "List scopes for a client");

        var clientId = new Option<string>("--client-id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(clientId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string cid, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var scopes = await client.ListScopesForClient(cid);

                if (scopes is null || scopes.Count == 0)
                {
                    Console.WriteLine(json ? "[]" : "(no scopes)");
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(scopes, MadJsonContext.Default.ListScopeObject));
                }
                else
                {
                    Console.WriteLine($"{"Id",-36} {"Name",-20} Description");
                    Console.WriteLine(new string('-', 100));
                    foreach (var s in scopes)
                        Console.WriteLine($"{s.Id,-36} {s.Name,-20} {s.Description}");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Exception while listing scopes: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine($"Failed to list scopes for client {cid}.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, adminToken, clientId, jsonOut);

        return cmd;
    }

    private static Command RemoveScopeCommand()
    {
        var cmd = new Command("remove-scope", "Remove a scope from a client");

        var clientId = new Option<string>("--client-id") { IsRequired = true };
        var scopeId = new Option<string>("--scope-id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(clientId);
        cmd.AddOption(scopeId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string cid, string sid, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.RemoveScopeFromClient(cid, sid);

                if (json)
                {
                    if (ok)
                    {
                        var result = new MessageResponse(true, "Scope removed.");
                        Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.MessageResponse));
                    }
                    else
                    {
                        var result = new ErrorResponse(false, "Failed to remove scope.");
                        Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.ErrorResponse));
                    }
                }
                else
                {
                    Console.WriteLine(ok ? "Scope removed." : "Failed to remove.");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error removing scope {sid} from client {cid}: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine($"Error removing scope {sid} from client {cid}.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, adminToken, clientId, scopeId, jsonOut);

        return cmd;
    }
}
