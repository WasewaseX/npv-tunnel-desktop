using NpvTunnel.Core.Security;
using Xunit;

namespace NpvTunnel.Core.Tests;

public sealed class RedactorTests
{
    [Fact]
    public void Uuid_IsScrubbed()
    {
        string scrubbed = Redactor.Scrub("id=11111111-2222-3333-4444-555555555555 connected");

        Assert.DoesNotContain("11111111-2222-3333-4444-555555555555", scrubbed);
    }

    [Fact]
    public void Passwords_AreScrubbed()
    {
        string scrubbed = Redactor.Scrub("password=hunter2 user=alice");

        Assert.DoesNotContain("hunter2", scrubbed);
        Assert.Contains("alice", scrubbed);
    }

    [Fact]
    public void ShareLinks_AreScrubbed()
    {
        string scrubbed = Redactor.Scrub("importing vless://11111111-2222-3333-4444-555555555555@example.com:443?pbk=abc");

        Assert.Contains("vless://", scrubbed);
        Assert.DoesNotContain("11111111", scrubbed);
        Assert.DoesNotContain("example.com:443", scrubbed);
    }

    [Theory]
    [InlineData("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def")]
    [InlineData("Authorization: Bearer abcdef123456")]
    public void AuthHeaders_AreScrubbed(string line)
    {
        Assert.DoesNotContain("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", Redactor.Scrub(line));
        Assert.DoesNotContain("abcdef123456", Redactor.Scrub(line));
    }

    [Fact]
    public void Null_AndEmpty_AreSafe()
    {
        Assert.Equal(string.Empty, Redactor.Scrub(null));
        Assert.Equal(string.Empty, Redactor.Scrub(string.Empty));
    }

    [Fact]
    public void OrdinaryText_SurvivesIntact()
    {
        const string line = "tunnel core started on 127.0.0.1:10808";

        Assert.Equal(line, Redactor.Scrub(line));
    }
}
