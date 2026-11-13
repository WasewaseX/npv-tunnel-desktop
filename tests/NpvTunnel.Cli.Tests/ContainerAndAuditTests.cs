using System.Text.Json;
using NpvTunnel.Cli;
using NpvTunnel.Core.Engine;
using NpvTunnel.Core.Import;
using NpvTunnel.Core.Models;
using NpvTunnel.Core.Security;
using Xunit;

namespace NpvTunnel.Cli.Tests;

/// <summary>
/// Checks the paths a Linux user actually hits: the encrypted container coming out
/// of a channel, the on-disk store, and the safety review that decides what is
/// allowed to reach the engine.
/// </summary>
public sealed class ContainerAndStoreTests
{
    [Fact]
    public void SyntheticContainerImportsEveryProfile()
    {
        ImportBatch batch = NpvtImporter.ImportAll(SelfTest.BuildContainer());

        Assert.True(batch.Success, batch.Message);
        Assert.Equal(2, batch.ImportedCount);
        Assert.All(batch.Profiles, profile => Assert.False(string.IsNullOrWhiteSpace(profile.Uuid)));
    }

    [Fact]
    public void StoreRoundTripsAndKeepsTheFilePrivate()
    {
        string dir = Path.Combine(Path.GetTempPath(), "npvt-store-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string path = Path.Combine(dir, "profiles.json");
            var store = new ProfileStore(path);
            ImportBatch batch = NpvtImporter.ImportAll(SelfTest.BuildContainer());
            store.Save(batch.Profiles);

            List<Profile> loaded = store.Load();
            Assert.Equal(2, loaded.Count);
            Assert.Equal(batch.Profiles[0].Id, loaded[0].Id);
            Assert.Equal(batch.Profiles[1].Address, loaded[1].Address);

            if (!OperatingSystem.IsWindows())
            {
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
            }

            // The store is sealed: no address or credential from the config appears in it.
            string raw = File.ReadAllText(path);
            Assert.DoesNotContain(batch.Profiles[0].Uuid, raw, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(batch.Profiles[1].Address, raw, StringComparison.OrdinalIgnoreCase);

            // Sealing must not cost the user their profiles: a second read still works.
            Assert.Equal(2, new ProfileStore(path).Load().Count);

            if (!OperatingSystem.IsWindows())
            {
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
                    File.GetUnixFileMode(dir));
            }
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void EngineDigestIsCheckedBeforeTheBinaryIsUsed()
    {
        string dir = Path.Combine(Path.GetTempPath(), "npvt-engine-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string engine = Path.Combine(dir, "xray");
            File.WriteAllText(engine, "not a real engine");

            var runner = new EngineRunner(engine);
            Assert.False(runner.VerifyDigest(out string missing), "a binary without a digest file must not be trusted");
            Assert.Contains("ENGINE.sha256", missing, StringComparison.Ordinal);

            string real = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(engine))).ToLowerInvariant();
            File.WriteAllText(Path.Combine(dir, "ENGINE.sha256"), real + "  xray\n");
            Assert.True(runner.VerifyDigest(out _));

            File.WriteAllText(Path.Combine(dir, "ENGINE.sha256"), new string('0', 64) + "  xray\n");
            Assert.False(runner.VerifyDigest(out string mismatch));
            Assert.Contains("mismatch", mismatch, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}

public sealed class AuditTests
{
    private static Profile Vless(string address, SecurityLayer security, int port = 443) => new()
    {
        Name = "audit sample",
        Protocol = ProfileProtocol.Vless,
        Address = address,
        Port = port,
        Uuid = "11111111-2222-3333-4444-555555555555",
        Transport = Transport.WebSocket,
        Path = "/ws",
        Security = security,
        Sni = security == SecurityLayer.None ? string.Empty : "example.com",
    };

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("192.168.1.4")]
    [InlineData("10.0.0.9")]
    [InlineData("172.16.0.1")]
    [InlineData("169.254.1.1")]
    [InlineData("100.64.0.1")]
    [InlineData("::1")]
    [InlineData("fd00::1")]
    public void PrivateEndpointsAreRefused(string address)
    {
        IReadOnlyList<ConfigAudit.Finding> findings = ConfigAudit.Review(Vless(address, SecurityLayer.Tls));
        Assert.True(ConfigAudit.BlocksConnect(findings));
    }

    [Fact]
    public void PlainVlessWithoutTlsCannotReachAPublicServer()
    {
        IReadOnlyList<ConfigAudit.Finding> findings = ConfigAudit.Review(Vless("example.com", SecurityLayer.None));
        Assert.True(ConfigAudit.BlocksConnect(findings));
    }

    [Fact]
    public void CleanTlsProfileIsAllowedWithoutNoise()
    {
        IReadOnlyList<ConfigAudit.Finding> findings = ConfigAudit.Review(Vless("example.com", SecurityLayer.Tls));
        Assert.False(ConfigAudit.BlocksConnect(findings));
        Assert.DoesNotContain(findings, finding => finding.Severity != ConfigAudit.Severity.Info);
    }

    [Fact]
    public void RealityWithoutAPublicKeyIsRefused()
    {
        Profile profile = Vless("example.com", SecurityLayer.Reality);
        profile.PublicKey = string.Empty;
        Assert.True(ConfigAudit.BlocksConnect(ConfigAudit.Review(profile)));

        profile.PublicKey = "SbVKOQ1pQ0FQGmHt7QfM0FrvHV6mn0yQ2rJ8jv3GZUY";
        Assert.False(ConfigAudit.BlocksConnect(ConfigAudit.Review(profile)));
    }

    [Fact]
    public void AllowInsecureIsReportedAndStrippedFromTheEngineConfig()
    {
        Profile profile = Vless("example.com", SecurityLayer.Tls);
        profile.AllowInsecure = true;
        Assert.Contains(ConfigAudit.Review(profile), finding => finding.Severity == ConfigAudit.Severity.Warning);

        EngineConfig config = XrayConfigBuilder.Build(profile, new EngineOptions());
        Assert.DoesNotContain("allowInsecure\\\":true", config.Json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BuiltConfigOnlyBindsTheLoopbackInterface()
    {
        string json = XrayConfigBuilder.Build(Vless("example.com", SecurityLayer.Tls), new EngineOptions()).Json;
        using JsonDocument document = JsonDocument.Parse(json);
        foreach (JsonElement inbound in document.RootElement.GetProperty("inbounds").EnumerateArray())
        {
            Assert.Equal("127.0.0.1", inbound.GetProperty("listen").GetString());
        }
    }
}
