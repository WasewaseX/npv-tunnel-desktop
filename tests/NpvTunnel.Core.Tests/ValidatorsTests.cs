using NpvTunnel.Core.Security;
using Xunit;

namespace NpvTunnel.Core.Tests;

public sealed class ValidatorsTests
{
    [Theory]
    [InlineData("example.com")]
    [InlineData("sub.example.com")]
    [InlineData("1.2.3.4")]
    [InlineData("2001:db8::1")]
    [InlineData("my-server_01")]
    public void SafeHosts_AreAccepted(string host) =>
        Assert.True(Validators.IsSafeHost(host), $"{host} should be a safe host");

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("example.com/path")]
    [InlineData("example.com;rm -rf /")]
    [InlineData("example com")]
    [InlineData("\"quoted\"")]
    [InlineData("-leading-dash")]
    [InlineData("host:443")]
    [InlineData("$(id)")]
    [InlineData("a`b")]
    public void UnsafeHosts_AreRejected(string? host) =>
        Assert.False(Validators.IsSafeHost(host), $"{host} should be rejected");

    [Theory]
    [InlineData(null, true)]
    [InlineData("/", true)]
    [InlineData("/ws", true)]
    [InlineData("/a/b/c?x=1", true)]
    [InlineData("/bad path", false)]
    [InlineData("no-leading-slash", true)]
    [InlineData("/traversal/..", false)]
    [InlineData("..", false)]
    [InlineData("/a\\b", false)]
    public void Paths_AreValidated(string? path, bool expected) =>
        Assert.Equal(expected, Validators.IsSafePath(path));

    [Theory]
    [InlineData(null, true)]
    [InlineData("", true)]
    [InlineData("abcd1234", true)]
    [InlineData("0123456789abcdef", true)]
    [InlineData("xyz", false)]
    [InlineData("abcd1234abcd12345", false)]
    public void ShortIds_AreValidated(string? sid, bool expected) =>
        Assert.Equal(expected, Validators.IsValidShortId(sid));

    [Fact]
    public void RealityKeys_AcceptOnlyBase64UrlOf32Bytes()
    {
        Assert.True(Validators.IsValidRealityKey("jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"));
        Assert.False(Validators.IsValidRealityKey("short"));
        Assert.False(Validators.IsValidRealityKey(null));
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(80, false)]
    [InlineData(1023, false)]
    [InlineData(1080, true)]
    [InlineData(65535, true)]
    [InlineData(65536, false)]
    public void LocalPorts_MustBeUnprivileged(int port, bool expected) =>
        Assert.Equal(expected, Validators.IsUsableLocalPort(port));
}
