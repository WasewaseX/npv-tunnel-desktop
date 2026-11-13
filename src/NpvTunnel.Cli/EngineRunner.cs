using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using NpvTunnel.Core.Engine;
using NpvTunnel.Core.Models;

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
    /// Digests are published in the release tarball as core/ENGINE.sha256. A binary
    /// that does not match is refused rather than executed.
    /// </summary>
    public bool VerifyDigest(out string message)
    {
        message = string.Empty;
        if (!File.Exists(BinaryPath))
        {
            message = $"The tunnel engine was not found at {BinaryPath}.";
            return false;
        }

        string digestFile = Path.Combine(Path.GetDirectoryName(BinaryPath) ?? ".", "ENGINE.sha256");
        if (!File.Exists(digestFile))
        {
            message = "No ENGINE.sha256 next to the binary, so the engine cannot be verified.";
            return false;
        }

        string expected = File.ReadAllText(digestFile).Split(' ', StringSplitOptions.RemoveEmptyEntries)[0].Trim().ToLowerInvariant();
        using FileStream stream = File.OpenRead(BinaryPath);
        string actual = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        if (!string.Equals(expected, actual, StringComparison.Ordinal))
        {
            message = $"Engine digest mismatch: expected {expected[..12]}…, got {actual[..12]}…";
            return false;
        }

        message = "Engine digest verified.";
        return true;
    }

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

        if (_configPath is not null && File.Exists(_configPath))
        {
            try
            {
                File.Delete(_configPath);
                string? dir = Path.GetDirectoryName(_configPath);
                if (dir is not null && Directory.Exists(dir))
                {
                    Directory.Delete(dir, recursive: true);
                }
            }
            catch (IOException)
            {
            }
        }
    }
}
