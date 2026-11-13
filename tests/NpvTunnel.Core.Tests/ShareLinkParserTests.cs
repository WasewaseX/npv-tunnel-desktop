using System.Text;
using System.Text.Json;
using NpvTunnel.Core.Import;
using NpvTunnel.Core.Models;
using Xunit;
using CoreUriParser = NpvTunnel.Core.Import.UriParser;

namespace NpvTunnel.Core.Tests;

public sealed class ShareLinkParserTests
{
    private const string VlessUri =
        "vless://11111111-2222-3333-4444-555555555555@example.com:443" +
        "?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome" +
        "&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=ab12&type=grpc#Frankfurt";

    [Fact]
    public void VlessRealityLink_IsParsed()
    {
        ImportResult result = CoreUriParser.Parse(VlessUri);

        Assert.True(result.Success, result.Message);
        Profile profile = Assert.IsType<Profile>(result.Profile);
        Assert.Equal(ProfileProtocol.Vless, profile.Protocol);
        Assert.Equal("example.com", profile.Address);
        Assert.Equal(443, profile.Port);
        Assert.Equal("11111111-2222-3333-4444-555555555555", profile.Uuid);
        Assert.Equal("Frankfurt", profile.Name);
    }

    [Fact]
    public void TrojanLink_CarriesPassword()
    {
        ImportResult result = CoreUriParser.Parse("trojan://s3cret@trojan.example.org:8443?sni=t.example.org#Frankfurt");

        Assert.True(result.Success, result.Message);
        Assert.Equal(ProfileProtocol.Trojan, result.Profile!.Protocol);
        Assert.Equal("s3cret", result.Profile.Password);
        Assert.Equal(8443, result.Profile.Port);
    }

    [Fact]
    public void ShadowsocksLink_DecodesBase64UserInfo()
    {
        string userInfo = Convert.ToBase64String(Encoding.UTF8.GetBytes("aes-256-gcm:pa55w0rd"))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

        ImportResult result = CoreUriParser.Parse($"ss://{userInfo}@ss.example.net:8388#Test");

        Assert.True(result.Success, result.Message);
        Assert.Equal(ProfileProtocol.Shadowsocks, result.Profile!.Protocol);
        Assert.Equal("aes-256-gcm", result.Profile.Method);
        Assert.Equal("pa55w0rd", result.Profile.Password);
    }

    [Fact]
    public void VmessLink_DecodesJson()
    {
        string json = JsonSerializer.Serialize(new
        {
            v = "2",
            ps = "VmessNode",
            add = "vm.example.com",
            port = "443",
            id = "11111111-2222-3333-4444-555555555555",
            aid = "0",
            scy = "auto",
            net = "ws",
            path = "/ws",
            host = "cdn.example.com",
            tls = "tls",
        });

        string payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
        ImportResult result = CoreUriParser.Parse("vmess://" + payload);

        Assert.True(result.Success, result.Message);
        Assert.Equal(ProfileProtocol.Vmess, result.Profile!.Protocol);
        Assert.Equal("vm.example.com", result.Profile.Address);
        Assert.Equal("VmessNode", result.Profile.Name);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not a link")]
    [InlineData("ftp://example.com/x")]
    public void Garbage_IsRejectedWithAnError(string input)
    {
        ImportResult result = CoreUriParser.Parse(input);

        Assert.False(result.Success);
        Assert.NotEqual(ImportError.None, result.Error);
    }

    [Fact]
    public void LooksLikeUri_OnlyMatchesSupportedSchemes()
    {
        Assert.True(CoreUriParser.LooksLikeUri(VlessUri));
        Assert.True(CoreUriParser.LooksLikeUri("https://example.com"));
        Assert.False(CoreUriParser.LooksLikeUri("ftp://example.com/x"));
        Assert.False(CoreUriParser.LooksLikeUri("just some text"));
    }

    [Fact]
    public void TruncatedVless_DoesNotThrow()
    {
        ImportResult result = CoreUriParser.Parse("vless://@:?&&#");

        Assert.False(result.Success);
        Assert.NotEqual(ImportError.None, result.Error);
    }
}
