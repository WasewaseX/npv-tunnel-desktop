using System.Globalization;
using System.Text;
using NpvTunnel.Core.Import;
using NpvTunnel.Core.Models;
using Xunit;
using Xunit.Sdk;

namespace NpvTunnel.Core.Tests;

/// <summary>
/// The vendor <c>.npvt</c> container: white-box cipher, block layout and the
/// profile reader. These are the files channels actually hand out, so this is the
/// path a real user exercises when they double-click a download.
/// </summary>
public sealed class NpvtContainerTests
{
    private const string WrapperJson = """
    [{"name":"Test Node","address":"example.com:443","type":"V2RAY","v2rayProfile":
    {"configVersion":4,"configType":5,"remarks":"Test Node","server":"example.com","serverPort":"443",
    "password":"11111111-2222-3333-4444-555555555555","method":"none","network":"ws","host":"cdn.example.com",
    "security":"tls","sni":"front.example.com","insecure":true,
    "v2rayJson":"{\"remarks\":\"Test Node\",\"outbounds\":[{\"tag\":\"proxy\",\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"example.com\",\"port\":443,\"users\":[{\"id\":\"11111111-2222-3333-4444-555555555555\",\"flow\":\"xtls-rprx-vision\",\"encryption\":\"none\"}]}]},\"streamSettings\":{\"network\":\"ws\",\"security\":\"tls\",\"wsSettings\":{\"path\":\"/ray\",\"headers\":{\"Host\":\"cdn.example.com\"}},\"tlsSettings\":{\"allowInsecure\":true,\"serverName\":\"front.example.com\",\"alpn\":[\"h2\",\"http/1.1\"]}}}]}"}}]
    """;

    [Fact]
    public void Cipher_MatchesTheReferenceKnownAnswer()
    {
        // The reference Go implementation documents this exact vector:
        // core(00 01 .. 0f) == 58bf2ecbd052f9cdb4704ac2b7fda375
        byte[] block = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        var output = new byte[16];

        NpvtWhitebox.Core(block, output);

        Assert.Equal(
            "58bf2ecbd052f9cdb4704ac2b7fda375",
            Convert.ToHexString(output).ToLowerInvariant());
    }

    [Fact]
    public void Cipher_RoundTrips()
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("the quick brown fox jumps over the lazy dog, twice over.");

        byte[] sealedBytes = Seal(plaintext);
        byte[] opened = NpvtWhitebox.Decrypt(sealedBytes);

        Assert.Equal(plaintext, opened);
    }

    [Fact]
    public void Container_WithLockAndVersionBlocks_ImportsEveryProfile()
    {
        string file = BuildContainer(
            "1",
            WrapperJson,
            "{\"version\":1,\"isLocked\":true,\"message\":\"join the channel\"}");

        ImportBatch batch = NpvtImporter.ImportAll(file);

        Assert.True(batch.Success, batch.Message);
        Profile profile = Assert.Single(batch.Profiles);
        Assert.Equal(ProfileProtocol.Vless, profile.Protocol);
        Assert.Equal("example.com", profile.Address);
        Assert.Equal(443, profile.Port);
        Assert.Equal("11111111-2222-3333-4444-555555555555", profile.Uuid);
        Assert.Equal(Transport.WebSocket, profile.Transport);
        Assert.Equal(SecurityLayer.Tls, profile.Security);
        Assert.Equal("/ray", profile.Path);
        Assert.Equal("cdn.example.com", profile.Host);
        Assert.Equal("front.example.com", profile.Sni);
        Assert.Equal("xtls-rprx-vision", profile.Flow);
    }

    [Fact]
    public void Container_NeverSilentlyDisablesTlsVerification()
    {
        string file = BuildContainer("1", WrapperJson, "{}");

        ImportBatch batch = NpvtImporter.ImportAll(file);

        Profile profile = Assert.Single(batch.Profiles);
        Assert.False(profile.AllowInsecure);
        Assert.Contains(batch.Results[0].Warnings, w => w.Contains("TLS verification", StringComparison.Ordinal));
    }

    [Fact]
    public void SingleImport_ReturnsTheFirstProfileOfAContainer()
    {
        ImportResult result = NpvtImporter.ImportText(BuildContainer("1", WrapperJson, "{}"));

        Assert.True(result.Success, result.Message);
        Assert.Equal("example.com", result.Profile!.Address);
    }

    [Fact]
    public void SubscriptionFlavour_IsUnderstood()
    {
        // NPVTSUB1 wraps exactly one blob instead of three.
        string file = "NPVTSUB1\n" + Encrypt(Encoding.UTF8.GetBytes(WrapperJson));

        ImportBatch batch = NpvtImporter.ImportAll(file);

        Assert.True(batch.Success, batch.Message);
        Assert.Single(batch.Profiles);
    }

    [Fact]
    public void DamagedContainer_IsRejectedWithAnExplanation()
    {
        ImportBatch batch = NpvtImporter.ImportAll("NPVT1\nnot*base64*at-all");

        Assert.False(batch.Success);
        Assert.False(string.IsNullOrWhiteSpace(batch.Message));
        Assert.DoesNotContain("Exception", batch.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void NpvsContainer_SaysWhatItIsInsteadOfGuessing()
    {
        ImportBatch batch = NpvtImporter.ImportAll("NPVS\u0005\u0000\u0001binary");

        Assert.False(batch.Success);
        Assert.Equal(ImportError.LegacyEncryptedConfig, batch.Error);
        Assert.Contains(".npvs", batch.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// <summary>
    /// The committed vendor fixture: a container handed out by a channel, with every
    /// endpoint, port and credential replaced by a placeholder. It is the same shape -
    /// three sealed blocks, seventeen profiles, the nested Xray JSON inside each - so the
    /// decryptor, the wrapper reader and the profile mapper are all exercised by an
    /// artefact that is always present.
    /// </summary>
    [Fact]
    public void VendorFixture_DecryptsAndYieldsEveryProfile()
    {
        string path = Path.Combine(AppContext.BaseDirectory, "fixtures", "vendor-channel-sanitized.npvt");
        Assert.True(File.Exists(path), $"missing fixture {path}");

        ImportBatch batch = NpvtImporter.ImportAll(File.ReadAllText(path), null, Path.GetFileName(path));

        Assert.True(batch.Success, batch.Message);
        Assert.Equal(17, batch.ImportedCount);
        Assert.Equal(0, batch.FailedCount);
        Assert.All(batch.Profiles, profile =>
        {
            Assert.Matches(@"^fixture-\d{2}\.example\.com$", profile.Address);
            Assert.InRange(profile.Port, 4001, 4017);
            Assert.False(string.IsNullOrWhiteSpace(profile.Name));
            Assert.NotEqual("x", profile.Security.ToString().ToLowerInvariant()[..1]);
        });

        // The fixture must never carry somebody's working subscription.
        string raw = File.ReadAllText(path);
        Assert.DoesNotContain("qarvian", raw, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Optional check against the upstream npvs sample container. CI downloads it and
    /// sets <c>NPVT_REAL_SAMPLE</c>, which makes this a real compatibility test on every
    /// push; when the variable is absent the test is reported as skipped instead of
    /// quietly passing.
    /// </summary>
    [SkippableFact]
    public void RealContainer_Decrypts_WhenSampleIsAvailable()
    {
        string? path = Environment.GetEnvironmentVariable("NPVT_REAL_SAMPLE");
        Skip.If(string.IsNullOrWhiteSpace(path) || !File.Exists(path),
            "NPVT_REAL_SAMPLE is not set; the vendor sample was not available for this run.");

        ImportBatch batch = NpvtImporter.ImportAll(File.ReadAllText(path!), null, Path.GetFileName(path!));

        Assert.True(batch.Success, batch.Message);
        Assert.True(batch.ImportedCount > 1, $"expected several profiles, got {batch.ImportedCount}: {batch.Message}");
        Assert.All(batch.Profiles, p =>
        {
            Assert.False(string.IsNullOrWhiteSpace(p.Address));
            Assert.InRange(p.Port, 1, 65535);
            Assert.False(string.IsNullOrWhiteSpace(p.Name));
        });
    }

    private static string BuildContainer(params string[] blocks) =>
        "NPVT1\n" + string.Join(",", blocks.Select(b => Encrypt(Encoding.UTF8.GetBytes(b)))) + "\n";

    /// <summary>CTR is symmetric, so sealing is the same call with a fresh nonce.</summary>
    private static string Encrypt(byte[] plaintext)
    {
        byte[] sealedBytes = Seal(plaintext);
        return Convert.ToBase64String(sealedBytes);
    }

    private static byte[] Seal(byte[] plaintext)
    {
        byte[] nonce = new byte[16];
        Random.Shared.NextBytes(nonce);
        byte[] payload = new byte[16 + plaintext.Length];
        nonce.CopyTo(payload, 0);
        plaintext.CopyTo(payload, 16);
        byte[] ciphertext = NpvtWhitebox.Decrypt(payload);
        ciphertext.CopyTo(payload, 16);
        return payload;
    }
}
