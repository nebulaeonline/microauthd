using FluentAssertions;

using madTypes.Api.Common;
using madTests.Common;
using madTests.Database;
using microauthd.Services;

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

    
}
