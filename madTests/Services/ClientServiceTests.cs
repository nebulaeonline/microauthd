using FluentAssertions;

using madTypes.Api.Common;
using madTypes.Api.Requests;
using madTests.Common;
using madTests.Database;
using microauthd.Services;
using microauthd.Data;

namespace madTests.Services;

public class ClientServiceTests
{
    [Fact]
    public void CreateClient_ShouldReturn_ClientObject_ForValidClient()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        var client = ClientService.CreateClient(new madTypes.Api.Requests.CreateClientRequest
        {
            ClientId = "validclient",
            ClientSecret = "validsecret",
            DisplayName = "Valid Client",
            Audience = "validaud"
        }, config).Value;

        client.Should().NotBeNull("A new client should return a Client Object.");
        client.ClientId.Should().Be("validclient", "Client ID should match the one provided.");
        
        TestDb.CleanupDb(config);
    }

    [Fact]
    public void UpdateClient_ShouldReturn_ClientObject_ForValidClient()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        var client = ClientService.CreateClient(new madTypes.Api.Requests.CreateClientRequest
        {
            ClientId = "validclient",
            ClientSecret = "validsecret",
            DisplayName = "Valid Client",
            Audience = "validaud"
        }, config).Value;

        client.Should().NotBeNull("A created client should not be null.");

        var updatedClient = ClientService.UpdateClient(client.Id, new ClientObject
        {
            Id = client.Id,
            ClientId = "validvalidvalidclient",
            DisplayName = "Updated Client",
            IsActive = true,
            Audience = "updatedaud"
        }, config).Value;

        updatedClient.Should().NotBeNull("An updated client should return a Client Object.");
        updatedClient.ClientId.Should().Be("validvalidvalidclient", "Client ID should match the one provided.");

        TestDb.CleanupDb(config);
    }

    [Fact]
    public void ListClients_ShouldReturn_AListOfCorrectSize()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        var client = ClientService.CreateClient(new madTypes.Api.Requests.CreateClientRequest
        {
            ClientId = "validclient",
            ClientSecret = "validsecret",
            DisplayName = "Valid Client",
            Audience = "validaud"
        }, config).Value;

        client.Should().NotBeNull("A created client should not be null.");

        var client2 = ClientService.CreateClient(new madTypes.Api.Requests.CreateClientRequest
        {
            ClientId = "validclient2",
            ClientSecret = "validsecret2",
            DisplayName = "Valid Client2",
            Audience = "validaud2"
        }, config).Value;

        client2.Should().NotBeNull("A second created client should not be null.");

        var client3 = ClientService.CreateClient(new madTypes.Api.Requests.CreateClientRequest
        {
            ClientId = "validclient3",
            ClientSecret = "validsecret3",
            DisplayName = "Valid Client3",
            Audience = "validaud3"
        }, config).Value;

        client3.Should().NotBeNull("A third created client should not be null.");

        var clientList = ClientService.GetAllClients().Value;

        clientList.Count.Should().Be(3);
        
        TestDb.CleanupDb(config);
    }

    [Fact]
    public void GetClientById_ShouldReturn_TheCorrectClient()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        var client = ClientService.CreateClient(new madTypes.Api.Requests.CreateClientRequest
        {
            ClientId = "validclient",
            ClientSecret = "validsecret",
            DisplayName = "Valid Client",
            Audience = "validaud"
        }, config).Value;

        client.Should().NotBeNull("A created client should not be null.");

        var retrievedClient = ClientService.GetClientById(client.Id).Value;

        retrievedClient.Should().NotBeNull("A retrieved client should not be null.");
        retrievedClient.Id.Should().Be(client.Id);
        retrievedClient.ClientId.Should().Be(client.ClientId, "The Client IDs should match.");

        TestDb.CleanupDb(config);
    }

    [Fact]
    public void GetClientIdByIdentifier_ShouldReturn_TheCorrectId()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        var client = ClientService.CreateClient(new madTypes.Api.Requests.CreateClientRequest
        {
            ClientId = "validclient",
            ClientSecret = "validsecret",
            DisplayName = "Valid Client",
            Audience = "validaud"
        }, config).Value;

        client.Should().NotBeNull("a created client should not be null.");

        var clientId = ClientService.GetClientIdByIdentifier(client.ClientId).Value;

        clientId.Should().NotBeNull("a retrieved client identifier should not be null.");
        clientId.Should().Be(client.Id);
        
        TestDb.CleanupDb(config);
    }

    [Fact]
    public void DeleteClient_Should_DeleteTheClient()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        var client = ClientService.CreateClient(new madTypes.Api.Requests.CreateClientRequest
        {
            ClientId = "validclient",
            ClientSecret = "validsecret",
            DisplayName = "Valid Client",
            Audience = "validaud"
        }, config).Value;

        client.Should().NotBeNull("A created client should not be null.");

        ClientService.DeleteClient(client.ClientId, config);

        var deletedClient = ClientService.GetClientById(client.Id).Value;

        deletedClient.Should().BeNull("A deleted client should be null.");

        TestDb.CleanupDb(config);
    }

    [Fact]
    public void RegenerateClientSecret_Should_Change_Hash()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        var client = ClientService.CreateClient(new madTypes.Api.Requests.CreateClientRequest
        {
            ClientId = "validclient",
            ClientSecret = "validsecret",
            DisplayName = "Valid Client",
            Audience = "validaud"
        }, config).Value;

        client.Should().NotBeNull("A created client should not be null.");

        var newClient = ClientStore.GetClientByClientIdentifier(client.ClientId);

        newClient.Should().NotBeNull("A retrieved client should not be null.");

        var originalSecretHash = newClient.ClientSecretHash;

        ClientService.RegenerateClientSecret(newClient.Id, config);

        var updatedClient = ClientStore.GetClientByClientIdentifier(client.ClientId);

        updatedClient.ClientSecretHash.Should().NotBe(originalSecretHash, "client secret hash should be different after regeneration.");
        
        TestDb.CleanupDb(config);
    }

    [Fact]
    public void ChangingClientSecret_Should_Change_Hash()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        var client = ClientService.CreateClient(new madTypes.Api.Requests.CreateClientRequest
        {
            ClientId = "validclient",
            ClientSecret = "validsecret",
            DisplayName = "Valid Client",
            Audience = "validaud"
        }, config).Value;

        client.Should().NotBeNull("A created client should not be null.");

        var newClient = ClientStore.GetClientByClientIdentifier(client.ClientId);

        newClient.Should().NotBeNull("A retrieved client should not be null.");

        var originalSecretHash = newClient.ClientSecretHash;

        ClientService.ChangeClientSecret(new ChangeClientSecretRequest
        (
            ClientId: newClient.Id,
            NewSecret: "validsecret2"
        ), config);

        var updatedClient = ClientStore.GetClientByClientIdentifier(client.ClientId);

        updatedClient.Should().NotBeNull("A retrieved client after changing secret should not be null.");

        updatedClient.ClientSecretHash.Should().NotBe(originalSecretHash, "client secret hash should be different after regeneration.");

        TestDb.CleanupDb(config);
    }

    [Fact]
    public void AddingAndRemovingClientRedirectURIs_Works_AsExpected()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);
        var client = ClientService.CreateClient(new madTypes.Api.Requests.CreateClientRequest
        {
            ClientId = "validclient",
            ClientSecret = "validsecret",
            DisplayName = "Valid Client",
            Audience = "validaud"
        }, config).Value;

        client.Should().NotBeNull("A created client should not be null.");

        var newClient = ClientStore.GetClientByClientIdentifier(client.ClientId);

        newClient.Should().NotBeNull("A retrieved client should not be null.");

        // Add redirect URIs
        ClientService.AddRedirectUri(newClient.Id, "https://example.com/callback");
        ClientService.AddRedirectUri(newClient.Id, "https://example.com/another-callback");

        var clientURIs = ClientStore.GetRedirectUrisByClientId(newClient.Id);

        clientURIs.Count().Should().Be(2, "There should be two redirect URIs after adding.");

        // Remove one redirect URI
        ClientStore.DeleteRedirectUriById(clientURIs.First().Id);

        var clientURIsAfterDelete = ClientStore.GetRedirectUrisByClientId(newClient.Id);

        clientURIsAfterDelete.Count().Should().Be(1, "There should be one redirect URI after deleting one.");

        TestDb.CleanupDb(config);
    }
}
