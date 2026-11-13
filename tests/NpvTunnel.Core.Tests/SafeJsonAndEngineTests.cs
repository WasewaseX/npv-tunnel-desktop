using System.Text.Json;
using NpvTunnel.Core.Engine;
using NpvTunnel.Core.Models;
using NpvTunnel.Core.Security;
using Xunit;

namespace NpvTunnel.Core.Tests;

public sealed class SafeJsonTests
{
    [Fact]
    public void OrdinaryDocument_Parses()
    {
        using JsonDocument doc = SafeJson.Parse("{\"a\":1,\"b\":[1,2,3]}");

        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
    }

    [Fact]
    public void OversizedDocument_Throws() =>
        Assert.Throws<SafeJson.JsonTooLargeException>(() => SafeJson.Parse("{\"a\":\"" + new string('a', 5000) + "\"}", 1024));

    [Fact]
    public void DeepNesting_Throws()
    {
        string deep = new string('[', 200) + new string(']', 200);

        Assert.ThrowsAny<Exception>(() => SafeJson.Parse(deep));
    }

    [Fact]
    public void TooManyNodes_Throws()
    {
        string wide = "[" + string.Join(',', Enumerable.Repeat("1", 25000)) + "]";

        Assert.ThrowsAny<Exception>(() => SafeJson.Parse(wide));
    }

    [Fact]
    public void InvalidJson_Throws() =>
        Assert.ThrowsAny<Exception>(() => SafeJson.Parse("{"));

    [Fact]
    public void PolicyConstants_AreNonZero()
    {
        Assert.True(SafeJson.DefaultMaxBytes > 0);
        Assert.True(SafeJson.DefaultMaxDepth > 0);
        Assert.True(SafeJson.DefaultMaxNodes > 0);
    }
}

public sealed class XrayConfigBuilderTests
{
    private static Profile Sample() => new()
    {
        Name = "Sample",
        Protocol = ProfileProtocol.Vless,
        Address = "example.com",
        Port = 443,
        Uuid = "11111111-2222-3333-4444-555555555555",
        Transport = Transport.Tcp,
        Security = SecurityLayer.Tls,
        Sni = "example.com",
    };

    [Fact]
    public void Build_EmitsRoutableConfig()
    {
        EngineOptions options = new() { SocksPort = 2080, HttpPort = 2081 };

        EngineConfig config = XrayConfigBuilder.Build(Sample(), options);

        using JsonDocument doc = JsonDocument.Parse(config.Json);
        string json = doc.RootElement.GetRawText();
        Assert.Contains("example.com", json);
        Assert.Contains("2080", json);
    }

    [Fact]
    public void Build_HonoursPorts()
    {
        EngineOptions options = new() { SocksPort = 11080, HttpPort = 11081 };

        EngineConfig config = XrayConfigBuilder.Build(Sample(), options);

        Assert.Contains("11080", config.Json);
        Assert.Contains("11081", config.Json);
    }

    [Fact]
    public void Build_NeverWritesAllowInsecureByDefault()
    {
        EngineConfig config = XrayConfigBuilder.Build(Sample(), new EngineOptions());

        Assert.DoesNotContain("allowInsecure\":true", config.Json.Replace(" ", string.Empty, StringComparison.Ordinal));
    }

    [Fact]
    public void Build_RejectsPrivilegedLocalPort()
    {
        EngineOptions options = new() { SocksPort = 22, HttpPort = 2081 };

        Assert.ThrowsAny<ArgumentException>(() =>
        {
            options.Validate();
            XrayConfigBuilder.Build(Sample(), options);
        });
    }
}
