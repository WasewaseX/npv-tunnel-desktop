using System.Text.RegularExpressions;
using NpvTunnel.Core.Engine;
using Xunit;

namespace NpvTunnel.Core.Tests;

/// <summary>
/// The engine digest is recorded in three places: the pins compiled into this build
/// (<see cref="EngineIntegrity.Known"/>), the Windows manifest the installer reads, and
/// the Linux publish script that stamps <c>core/ENGINE.sha256</c> into the archive. They
/// must agree, or a release ships a binary the application then refuses to run. This test
/// is the check that makes that impossible to forget.
/// </summary>
public sealed class EnginePinDriftTests
{
    private static string RepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "NpvTunnel.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("Could not find the repository root above " + AppContext.BaseDirectory);
    }

    [Fact]
    public void TheWindowsManifestMatchesTheCompiledPin()
    {
        string source = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "NpvTunnel.App", "Services", "EngineManifest.cs"));
        Match match = Regex.Match(source, @"PipelineSha256\s*=\s*""([0-9a-f]{64})""");
        Assert.True(match.Success, "EngineManifest.PipelineSha256 not found");

        Assert.Equal(EngineIntegrity.EmbeddedDigest("win-x64"), match.Groups[1].Value);
    }

    [Fact]
    public void TheLinuxPublishScriptMatchesTheCompiledPins()
    {
        string source = File.ReadAllText(Path.Combine(RepositoryRoot(), "scripts", "publish-linux.ps1"));

        // The script declares one { Runtime, BinarySha } pair per architecture.
        MatchCollection runtimes = Regex.Matches(source, @"Runtime\s*=\s*'([a-z0-9-]+)'");
        var declared = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match runtime in runtimes)
        {
            int window = source.IndexOf(runtime.Value, StringComparison.Ordinal);
            Match sha = Regex.Match(source[window..], @"BinarySha\s*=\s*'([0-9a-f]{64})'");
            Assert.True(sha.Success, "no BinarySha after " + runtime.Value);
            declared[runtime.Groups[1].Value] = sha.Groups[1].Value;
        }

        Assert.NotEmpty(declared);
        foreach ((string runtime, string digest) in declared)
        {
            Assert.Equal(EngineIntegrity.EmbeddedDigest(runtime), digest);
        }
    }

    [Fact]
    public void EveryKnownPinIsForAPlatformTheBuildsTarget()
    {
        string[] expected = { "win-x64", "linux-x64", "linux-arm64" };
        Assert.Equal(expected, EngineIntegrity.Known.Select(k => k.Runtime).OrderBy(r => Array.IndexOf(expected, r)));
        Assert.Equal(3, EngineIntegrity.Known.Select(k => k.Sha256).Distinct().Count());
    }
}
