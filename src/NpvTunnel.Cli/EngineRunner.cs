using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using NpvTunnel.Core.Engine;
using NpvTunnel.Core.Models;
using NpvTunnel.Core.Security;

namespace NpvTunnel.Cli;

/// <summary>
/// Runs the Xray core on Linux: locate the pinned binary, verify its digest,
/// write the generated config to a private file, start the process without a
/// shell, and take it down on exit.
/// </summary>
public sealed class EngineRunner : IDisposable
{
    private Process? _process;
    private string? _configPath;
    private bool _disposed;

    public EngineRunner(string binaryPath)
    {
        BinaryPath = binaryPath;
    }

    public string BinaryPath { get; private set; }

    /// <summary>
    /// Verified against the digest compiled into this build. The core/ENGINE.sha256 in
    /// the release archive is only accepted when it agrees with that pin: a digest file
    /// next to the binary can be swapped along with the binary, so it cannot be the
    /// authority. <paramref name="trustCustomEngine"/> is the explicit opt-in a user
    /// needs to run an engine this build knows nothing about.
    /// </summary>
    public bool VerifyDigest(out string message, bool trustCustomEngine = false)
    {
        EngineIntegrity.Verdict verdict = trustCustomEngine
            ? EngineIntegrity.VerifyCustom(BinaryPath)
            : EngineIntegrity.VerifyBundled(BinaryPath, EngineIntegrity.EmbeddedDigest());

        message = verdict.Message;
        return verdict.Trusted;
    }

    /// <summary>True when the binary was chosen by the user rather than shipped with the release.</summary>
    public bool IsCustom { get; init; }

    public string WriteConfig(Profile profile, EngineOptions options)
    {
        EngineOptions validated = options;
        validated.Validate();

        EngineConfig config = XrayConfigBuilder.Build(profile, validated);

        string dir = Path.Combine(Path.GetTempPath(), "npvtunnel-" + Environment.ProcessId);
        Directory.CreateDirectory(dir);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        _configPath = Path.Combine(dir, "config.json");
        File.WriteAllText(_configPath, config.Json, new UTF8Encoding(false));
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(_configPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        return _configPath;
    }

    /// <summary>Validates a config with the engine's own parser: <c>xray run -test</c>.</summary>
    public bool TestConfig(string configPath, out string output)
    {
        var info = new ProcessStartInfo(BinaryPath)
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        info.ArgumentList.Add("run");
        info.ArgumentList.Add("-test");
        info.ArgumentList.Add("-c");
        info.ArgumentList.Add(configPath);

        using Process process = Process.Start(info) ?? throw new InvalidOperationException("The engine could not be started.");
        string stderr = process.StandardError.ReadToEnd();
        string stdout = process.StandardOutput.ReadToEnd();
        process.WaitForExit(15000);
        output = (stdout + stderr).Trim();
        return process.HasExited && process.ExitCode == 0;
    }

    public bool Start(string configPath, out string message)
    {
        var info = new ProcessStartInfo(BinaryPath)
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        info.ArgumentList.Add("run");
        info.ArgumentList.Add("-c");
        info.ArgumentList.Add(configPath);

        _process = Process.Start(info);
        if (_process is null)
        {
            message = "The engine could not be started.";
            return false;
        }

        // The core prints to stderr; draining it keeps the pipe from filling up.
        _process.ErrorDataReceived += (_, e) => { };
        _process.BeginErrorReadLine();

        Thread.Sleep(700);
        if (_process.HasExited)
        {
            message = $"The engine exited immediately with code {_process.ExitCode}.";
            return false;
        }

        // The core reads its config once, at startup. Shredding the file now means the
        // credentials it carries are on disk for milliseconds instead of for the whole
        // session, and a crash cannot leave them behind.
        ShredConfig();

        message = "Engine started.";
        return true;
    }

    public void Stop()
    {
        if (_process is null || _process.HasExited)
        {
            return;
        }

        try
        {
            _process.Kill(entireProcessTree: true);
            _process.WaitForExit(5000);
        }
        catch (InvalidOperationException)
        {
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        Stop();
        _process?.Dispose();
        ShredConfig();
    }

    /// <summary>Overwrites and removes the generated config, then its private directory.</summary>
    public void ShredConfig()
    {
        string? configPath = _configPath;
        _configPath = null;
        if (configPath is null)
        {
            return;
        }

        try
        {
            SecretShredder.ShredFile(configPath);
            string? dir = Path.GetDirectoryName(configPath);
            if (dir is not null && Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
