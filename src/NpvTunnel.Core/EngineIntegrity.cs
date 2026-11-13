using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace NpvTunnel.Core.Engine;

/// <summary>
/// Decides whether a tunnel engine binary is the one this build was tested with.
///
/// The digest compiled into the application is the authority. A file named
/// <c>ENGINE.sha256</c> next to the binary is a convenience for the release
/// archive, not a trust anchor: anyone able to replace the engine can replace its
/// sidecar too, so a sidecar that disagrees with the build is treated as tampering
/// rather than as an update. Running a different engine is possible, but only when
/// the user says so explicitly.
/// </summary>
public static class EngineIntegrity
{
    public sealed record KnownEngine(string Runtime, string FileName, string Sha256);

    /// <summary>The engines this build ships with or downloads, by runtime identifier.</summary>
    public static IReadOnlyList<KnownEngine> Known { get; } = new[]
    {
        new KnownEngine("win-x64", "xray.exe", "1ca7a2cf61ba2c5d20b21a80d405b57933939751081cb289f07bd8ddf7cc3185"),
        new KnownEngine("linux-x64", "xray", "e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d"),
        new KnownEngine("linux-arm64", "xray", "c2d1e66a130556d32089adcf38202fcb6f9027e41fb456cc2cda9a5fabdc093a"),
    };

    public sealed record Verdict(bool Trusted, bool Custom, string Message);

    public static string CurrentRuntime()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return "win-x64";
        }

        string arch = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.Arm64 => "arm64",
            _ => "x64",
        };

        return "linux-" + arch;
    }

    /// <summary>The digest compiled into this build for the current platform, if known.</summary>
    public static string? EmbeddedDigest() => EmbeddedDigest(CurrentRuntime());

    public static string? EmbeddedDigest(string runtime)
    {
        foreach (KnownEngine engine in Known)
        {
            if (string.Equals(engine.Runtime, runtime, StringComparison.OrdinalIgnoreCase))
            {
                return engine.Sha256;
            }
        }

        return null;
    }

    public static string ComputeSha256(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.SequentialScan);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    /// <summary>The first field of the sidecar line, or null when there is no usable sidecar.</summary>
    public static string? ReadSidecar(string binaryPath)
    {
        string? directory = Path.GetDirectoryName(Path.GetFullPath(binaryPath));
        if (string.IsNullOrEmpty(directory))
        {
            return null;
        }

        string path = Path.Combine(directory, "ENGINE.sha256");
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            string first = File.ReadAllText(path).Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)[0].Trim();
            return first.Length == 64 ? first.ToLowerInvariant() : null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Verifies a bundled engine against the digest compiled into this build.
    /// </summary>
    /// <param name="binaryPath">The engine to check.</param>
    /// <param name="embeddedDigest">Digest compiled into the application, or null when this build has none for the platform.</param>
    public static Verdict VerifyBundled(string binaryPath, string? embeddedDigest)
    {
        if (!File.Exists(binaryPath))
        {
            return new Verdict(false, false, $"The tunnel engine was not found at {binaryPath}.");
        }

        if (string.IsNullOrEmpty(embeddedDigest))
        {
            return new Verdict(false, false,
                "This build carries no digest for the engine on this platform, so it cannot verify one. Use the release archive for this platform.");
        }

        string? sidecar = ReadSidecar(binaryPath);
        if (sidecar is not null && !string.Equals(sidecar, embeddedDigest, StringComparison.OrdinalIgnoreCase))
        {
            return new Verdict(false, false,
                "The ENGINE.sha256 next to the engine does not match the digest compiled into this build. " +
                "A digest file can be replaced as easily as a binary, so this is treated as tampering: reinstall from the official release.");
        }

        string actual = ComputeSha256(binaryPath);
        if (!string.Equals(actual, embeddedDigest, StringComparison.OrdinalIgnoreCase))
        {
            return new Verdict(false, false,
                $"The tunnel engine failed its integrity check and was not started (expected {embeddedDigest[..12]}…, found {actual[..12]}…). Reinstall from the official release.");
        }

        return new Verdict(true, false, "Engine digest verified against the build's own pin.");
    }

    /// <summary>
    /// Verifies an engine the user pointed at themselves. Nothing about that binary is
    /// pinned by this build, so the sidecar (when present) is all that can be checked,
    /// and only an explicit opt-in reaches this point.
    /// </summary>
    public static Verdict VerifyCustom(string binaryPath)
    {
        if (!File.Exists(binaryPath))
        {
            return new Verdict(false, true, $"The configured engine path does not exist: {binaryPath}");
        }

        string? sidecar = ReadSidecar(binaryPath);
        if (sidecar is null)
        {
            return new Verdict(true, true,
                "Custom engine: no ENGINE.sha256 beside it, so nothing was verified. You chose this binary; it runs as you.");
        }

        string actual = ComputeSha256(binaryPath);
        if (!string.Equals(actual, sidecar, StringComparison.OrdinalIgnoreCase))
        {
            return new Verdict(false, true,
                $"The custom engine does not match the ENGINE.sha256 beside it (expected {sidecar[..12]}…, found {actual[..12]}…). It was not started.");
        }

        return new Verdict(true, true, "Custom engine matches its own digest file; the build's pin does not cover it.");
    }
}
