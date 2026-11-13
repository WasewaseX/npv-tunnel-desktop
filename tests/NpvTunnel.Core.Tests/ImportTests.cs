using System.Text;
using NpvTunnel.Core.Import;
using NpvTunnel.Core.Models;
using NpvTunnel.Core.Security;
using Xunit;

namespace NpvTunnel.Core.Tests;

public sealed class ImportTests : IDisposable
{
    private const string VlessJson = """
        {
          "schema": "npvt/1",
          "name": "Round Trip",
          "protocol": "vless",
          "address": "example.com",
          "port": 443,
          "uuid": "11111111-2222-3333-4444-555555555555",
          "flow": "",
          "transport": "tcp",
          "tls": true,
          "sni": "example.com"
        }
        """;

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "npvt-tests-" + Guid.NewGuid().ToString("N"));

    public ImportTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
            // best effort
        }
    }

    [Theory]
    [InlineData("a.npvt", true)]
    [InlineData("a.NPVT", true)]
    [InlineData("a.inpv", true)]
    [InlineData("a.json", true)]
    [InlineData("a.exe", false)]
    [InlineData("a", false)]
    public void SupportedExtensions_AreRecognised(string file, bool expected) =>
        Assert.Equal(expected, NpvtImporter.IsSupportedExtension(file));

    [Fact]
    public void NpvtJson_Imports()
    {
        ImportResult result = NpvtImporter.ImportText(VlessJson, null, "round.npvt");

        Assert.True(result.Success, result.Message);
        Assert.Equal(ProfileProtocol.Vless, result.Profile!.Protocol);
        Assert.Equal("example.com", result.Profile.Address);
        Assert.Equal(443, result.Profile.Port);
    }

    [Fact]
    public void LockedEnvelope_NeedsThePassphrase_AndThenImports()
    {
        string envelope = LockedConfig.Lock(VlessJson, "correct horse battery staple");

        ImportResult withoutPassword = NpvtImporter.ImportText(envelope);
        Assert.False(withoutPassword.Success);
        Assert.Equal(ImportError.EncryptedNeedsPassword, withoutPassword.Error);

        ImportResult wrongPassword = NpvtImporter.ImportText(envelope, "hunter2");
        Assert.False(wrongPassword.Success);
        Assert.Equal(ImportError.BadPassword, wrongPassword.Error);

        ImportResult unlocked = NpvtImporter.ImportText(envelope, "correct horse battery staple");
        Assert.True(unlocked.Success, unlocked.Message);
        Assert.Equal("example.com", unlocked.Profile!.Address);
    }

    [Fact]
    public void LockedEnvelope_LeaksNoPlaintext()
    {
        string envelope = LockedConfig.Lock(VlessJson, "long-enough-passphrase");

        Assert.True(LockedConfig.IsEnvelope(envelope));
        Assert.DoesNotContain("example.com", envelope);
        Assert.DoesNotContain("11111111-2222", envelope);
        Assert.DoesNotContain("Round Trip", envelope);
    }

    [Fact]
    public void OversizedFile_IsRejectedBeforeParsing()
    {
        string path = Path.Combine(_dir, "huge.npvt");
        File.WriteAllText(path, new string('x', (1024 * 1024) + 16), Encoding.UTF8);

        ImportResult result = NpvtImporter.ImportFile(path);

        Assert.False(result.Success);
        Assert.Equal(ImportError.TooLarge, result.Error);
    }

    [Fact]
    public void MissingFile_FailsCleanly()
    {
        ImportResult result = NpvtImporter.ImportFile(Path.Combine(_dir, "nope.npvt"));

        Assert.False(result.Success);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
    }

    [Fact]
    public void EmptyText_IsEmptyError()
    {
        Assert.Equal(ImportError.Empty, NpvtImporter.ImportText("   ").Error);
    }

    [Fact]
    public void MalformedJson_FailsWithoutThrowing()
    {
        ImportResult result = NpvtImporter.ImportText("{ \"schema\": \"npvt/1\", ");

        Assert.False(result.Success);
        Assert.NotEqual(ImportError.None, result.Error);
    }

    [Fact]
    public void DangerousHost_InJson_IsRejected()
    {
        string json = VlessJson.Replace("\"example.com\"", "\"example.com;rm -rf /\"", StringComparison.Ordinal);

        Assert.False(NpvtImporter.ImportText(json).Success);
    }
}
