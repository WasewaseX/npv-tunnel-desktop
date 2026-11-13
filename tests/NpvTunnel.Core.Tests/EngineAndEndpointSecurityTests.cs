using System.Net;
using System.Text.Json;
using NpvTunnel.Core.Engine;
using NpvTunnel.Core.Models;
using NpvTunnel.Core.Security;
using Xunit;

namespace NpvTunnel.Core.Tests;

/// <summary>
/// The engine is only trusted when it matches the digest built into the application,
/// and the endpoint is only trusted once its name has been resolved and the answer
/// checked. Both are boundaries, so both are tested against the attack rather than the
/// happy path.
/// </summary>
public sealed class EngineIntegrityTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "npvt-integrity-" + Guid.NewGuid().ToString("N"));

    public EngineIntegrityTests() => Directory.CreateDirectory(_directory);

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private string WriteEngine(string content, string? sidecar)
    {
        string path = Path.Combine(_directory, "xray");
        File.WriteAllText(path, content);
        if (sidecar is not null)
        {
            File.WriteAllText(Path.Combine(_directory, "ENGINE.sha256"), sidecar + "  xray\n");
        }

        return path;
    }

    [Fact]
    public void BundledEngine_MatchingTheBuild_IsAccepted()
    {
        string path = WriteEngine("engine bytes", null);
        string digest = EngineIntegrity.ComputeSha256(path);

        EngineIntegrity.Verdict verdict = EngineIntegrity.VerifyBundled(path, digest);

        Assert.True(verdict.Trusted, verdict.Message);
        Assert.False(verdict.Custom);
    }

    [Fact]
    public void ModifiedEngine_IsRefused()
    {
        string path = WriteEngine("engine bytes", null);
        string digest = EngineIntegrity.ComputeSha256(path);
        File.WriteAllText(path, "engine bytes, now with a backdoor");

        EngineIntegrity.Verdict verdict = EngineIntegrity.VerifyBundled(path, digest);

        Assert.False(verdict.Trusted);
        Assert.Contains("integrity check", verdict.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReplacedSidecar_CannotOverruleTheBuild()
    {
        // The attack the review described: swap the binary and its ENGINE.sha256 so the
        // pair agrees with itself. The digest compiled into the build is what decides.
        const string evil = "a malicious engine";
        string evilDigest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(evil))).ToLowerInvariant();
        string path = WriteEngine(evil, evilDigest);

        EngineIntegrity.Verdict verdict = EngineIntegrity.VerifyBundled(path, new string('0', 64));

        Assert.False(verdict.Trusted);
        Assert.Contains("ENGINE.sha256", verdict.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingSidecar_IsFineBecauseTheBuildStillHasThePin()
    {
        string path = WriteEngine("engine bytes", null);

        Assert.True(EngineIntegrity.VerifyBundled(path, EngineIntegrity.ComputeSha256(path)).Trusted);
    }

    [Fact]
    public void CustomEngine_MustMatchItsOwnDigestFile()
    {
        string path = WriteEngine("my own build", new string('1', 64));

        EngineIntegrity.Verdict verdict = EngineIntegrity.VerifyCustom(path);

        Assert.False(verdict.Trusted);
        Assert.True(verdict.Custom);
    }

    [Fact]
    public void CustomEngine_WithoutAnyDigest_IsFlaggedAsUnverified()
    {
        string path = WriteEngine("my own build", null);

        EngineIntegrity.Verdict verdict = EngineIntegrity.VerifyCustom(path);

        Assert.True(verdict.Trusted);
        Assert.True(verdict.Custom);
        Assert.Contains("nothing was verified", verdict.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EveryShippedPlatform_HasAPinAndItLooksLikeADigest()
    {
        foreach (EngineIntegrity.KnownEngine engine in EngineIntegrity.Known)
        {
            Assert.Equal(64, engine.Sha256.Length);
            Assert.Matches("^[0-9a-f]{64}$", engine.Sha256);
            Assert.Equal(engine.Sha256, EngineIntegrity.EmbeddedDigest(engine.Runtime));
        }
    }
}

public sealed class EndpointResolutionTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.1.2.3")]
    [InlineData("192.168.0.10")]
    [InlineData("169.254.169.254")]
    [InlineData("::1")]
    [InlineData("fd12:3456::1")]
    public void PrivateAddressesAreClassifiedAsPrivate(string value)
    {
        Assert.True(IPAddress.Parse(value).IsPrivate());
    }

    [Theory]
    [InlineData("192.0.2.5")]
    [InlineData("198.51.100.7")]
    [InlineData("203.0.113.9")]
    public void DocumentationRangesCountAsUnusable(string value)
    {
        Assert.True(IPAddress.Parse(value).IsPrivate());
    }

    [Theory]
    [InlineData("1.1.1.1")]
    [InlineData("146.75.57.111")]
    [InlineData("2606:4700:4700::1111")]
    public void PublicAddressesAreNot(string value)
    {
        Assert.False(IPAddress.Parse(value).IsPrivate());
    }

    [Fact]
    public void ALiteralEndpointIsReportedAsALiteral()
    {
        EndpointResolver.Resolution resolution = EndpointResolver.Resolve("93.184.216.34");

        Assert.True(resolution.IsLiteral);
        Assert.True(resolution.Resolved);
        Assert.Single(resolution.PublicAddresses);
        Assert.Empty(resolution.PrivateAddresses);
    }

    [Fact]
    public void ANameThatResolvesIntoPrivateSpaceIsCaught()
    {
        // 192.168.1.1 and a public address together: a rebinding answer with one bad
        // record has to be refused, not averaged.
        EndpointResolver.Resolution mixed = EndpointResolver.Classify(
            "rebind.example.net",
            new[] { IPAddress.Parse("192.168.1.1"), IPAddress.Parse("93.184.216.34") });

        Assert.True(mixed.HasPrivate);
        Assert.Equal("192.168.1.1", mixed.PrivateAddresses.Single().ToString());
        Assert.Null(EndpointResolver.PinCandidate(mixed, preferIpv4: true));
    }

    [Fact]
    public void ARefusedProfileNeverProducesAPin()
    {
        var profile = new Profile
        {
            Name = "rebind",
            Protocol = ProfileProtocol.Vless,
            Address = "rebind.example.net",
            Port = 443,
            Uuid = "11111111-2222-3333-4444-555555555555",
            Security = SecurityLayer.Tls,
            Sni = "rebind.example.net",
        };

        EndpointResolver.Resolution resolution = EndpointResolver.Classify(
            profile.Address,
            new[] { IPAddress.Parse("10.0.0.5") });

        IReadOnlyList<ConfigAudit.Finding> findings = ConfigAudit.Review(profile, resolution);

        Assert.True(ConfigAudit.BlocksConnect(findings));
        Assert.Contains(findings, f => f.Severity == ConfigAudit.Severity.Refused && f.Message.Contains("resolves to", StringComparison.Ordinal));
    }

    [Fact]
    public void AHealthyNameIsPinnedAndTheEngineDialsTheAuditedAddress()
    {
        var profile = new Profile
        {
            Name = "cdn",
            Protocol = ProfileProtocol.Vless,
            Address = "edge.example.net",
            Port = 443,
            Uuid = "11111111-2222-3333-4444-555555555555",
            Transport = Transport.WebSocket,
            Path = "/ws",
            Host = "cdn.example.com",
            Security = SecurityLayer.Tls,
            Sni = "cdn.example.com",
        };

        EndpointResolver.Resolution resolution = EndpointResolver.Classify(
            profile.Address,
            new[] { IPAddress.Parse("146.75.57.111") });

        var options = new EngineOptions { PinnedEndpointAddress = "146.75.57.111" };
        string json = XrayConfigBuilder.Build(profile, options).Json;

        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement hosts = document.RootElement.GetProperty("dns").GetProperty("hosts");
        Assert.Equal("146.75.57.111", hosts.GetProperty("edge.example.net")[0].GetString());

        Assert.False(ConfigAudit.BlocksConnect(ConfigAudit.Review(profile, resolution)));
    }

    [Fact]
    public void PinningCanBeTurnedOffAndIsSkippedForLiteralAddresses()
    {
        Profile literal = new()
        {
            Name = "direct",
            Protocol = ProfileProtocol.Vless,
            Address = "93.184.216.34",
            Port = 443,
            Uuid = "11111111-2222-3333-4444-555555555555",
            Security = SecurityLayer.Tls,
            Sni = "example.com",
        };

        string withPin = XrayConfigBuilder.Build(literal, new EngineOptions { PinnedEndpointAddress = "93.184.216.34" }).Json;
        using (JsonDocument document = JsonDocument.Parse(withPin))
        {
            Assert.False(document.RootElement.GetProperty("dns").TryGetProperty("hosts", out _));
        }

        literal.Address = "edge.example.net";
        string disabled = XrayConfigBuilder.Build(
            literal,
            new EngineOptions { PinnedEndpointAddress = "146.75.57.111", PinResolvedEndpoint = false }).Json;
        using (JsonDocument document = JsonDocument.Parse(disabled))
        {
            Assert.False(document.RootElement.GetProperty("dns").TryGetProperty("hosts", out _));
        }
    }
}

public sealed class SecretShredderTests
{
    [Fact]
    public void ShreddingReplacesTheBytesAndRemovesTheFile()
    {
        string directory = Path.Combine(Path.GetTempPath(), "npvt-shred-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            string path = Path.Combine(directory, "config.json");
            File.WriteAllText(path, "{\"uuid\":\"11111111-2222-3333-4444-555555555555\"}");

            Assert.True(SecretShredder.ShredFile(path));
            Assert.False(File.Exists(path));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void StaleRuntimeFilesAreSweptButFreshOnesAreLeftAlone()
    {
        string directory = Path.Combine(Path.GetTempPath(), "npvt-sweep-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            string stale = Path.Combine(directory, "session-old", "config.json");
            Directory.CreateDirectory(Path.GetDirectoryName(stale)!);
            File.WriteAllText(stale, "{\"uuid\":\"old\"}");
            Directory.SetLastWriteTimeUtc(Path.GetDirectoryName(stale)!, DateTime.UtcNow.AddDays(-2));

            string fresh = Path.Combine(directory, "session-new", "config.json");
            Directory.CreateDirectory(Path.GetDirectoryName(fresh)!);
            File.WriteAllText(fresh, "{\"uuid\":\"new\"}");

            int removed = SecretShredder.SweepStale(directory, TimeSpan.FromHours(1));

            Assert.Equal(1, removed);
            Assert.False(Directory.Exists(Path.GetDirectoryName(stale)!));
            Assert.True(File.Exists(fresh));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
