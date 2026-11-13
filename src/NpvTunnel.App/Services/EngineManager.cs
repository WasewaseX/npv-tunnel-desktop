using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NpvTunnel.Core.Engine;
using NpvTunnel.Core.Security;

namespace NpvTunnel.App.Services;

public sealed class EngineManager : IDisposable
{
    private struct IoCounters
    {
        public ulong ReadOperationCount;

        public ulong WriteOperationCount;

        public ulong OtherOperationCount;

        public ulong ReadTransferCount;

        public ulong WriteTransferCount;

        public ulong OtherTransferCount;
    }

    private readonly LogService _log;

    private readonly object _gate = new object();

    private Process? _process;

    private string? _configPath;

    private volatile bool _stopping;

    public bool IsRunning
    {
        get
        {
            lock (_gate)
            {
                Process? process = _process;
                return process != null && !process.HasExited;
            }
        }
    }

    public int? ProcessId
    {
        get
        {
            lock (_gate)
            {
                Process? process = _process;
                return (process != null && !process.HasExited) ? new int?(process.Id) : null;
            }
        }
    }

    public string? EnginePath { get; private set; }

    public event EventHandler<int>? CoreExited;

    public EngineManager(LogService log)
    {
        _log = log;
    }

    public string ResolveEnginePath(AppSettings settings)
    {
        // Only the engine this build was tested with runs from the window. A path left
        // in an older settings file is reported and ignored rather than trusted: the
        // GUI has no way to ask the user to vouch for an unknown binary, and silently
        // running one would defeat the digest pin below.
        if (!string.IsNullOrWhiteSpace(settings.CustomEnginePath))
        {
            _log.Warn("engine", "Ignoring the custom engine path in settings (" + settings.CustomEnginePath + "). The window runs the bundled, pinned engine; use the command-line build if you really need another binary.");
        }

        string[] array = new string[3]
        {
            Path.Combine(AppPaths.InstallDirectory, "core", "xray.exe"),
            Path.Combine(AppPaths.InstallDirectory, "xray.exe"),
            Path.Combine(AppPaths.InstallDirectory, "engine", "xray.exe")
        };
        foreach (string text in array)
        {
            if (File.Exists(text))
            {
                return text;
            }
        }
        throw new EngineException("The tunnel engine is not installed. Download it from Settings → Engine, or unpack the full release archive so that core\\xray.exe sits next to NpvTunnel.exe.");
    }

    /// <summary>
    /// The digest compiled into this build decides. The ENGINE.sha256 in the release
    /// archive is accepted only when it agrees with that pin - a sidecar can be
    /// replaced together with the binary, so it cannot be the authority. Running some
    /// other engine is possible only through the explicit custom-engine switch.
    /// </summary>
    public static EngineIntegrity.Verdict VerifyIntegrity(string enginePath, bool isCustom)
    {
        EngineIntegrity.Verdict verdict = isCustom
            ? EngineIntegrity.VerifyCustom(enginePath)
            : EngineIntegrity.VerifyBundled(enginePath, EngineIntegrity.EmbeddedDigest() ?? EngineManifest.PipelineSha256);

        if (!verdict.Trusted)
        {
            throw new EngineException(verdict.Message);
        }

        return verdict;
    }

    private static string ComputeSha256(string path)
    {
        using FileStream source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920);
        return Convert.ToHexString(SHA256.HashData(source));
    }

    public async Task StartAsync(AppSettings settings, string configJson, int socksPort, int httpPort, CancellationToken cancellationToken)
    {
        if (IsRunning)
        {
            throw new EngineException("The tunnel is already running.");
        }
        const bool custom = false;
        string engine = ResolveEnginePath(settings);
        EngineIntegrity.Verdict verdict = VerifyIntegrity(engine, custom);
        EnginePath = engine;
        if (verdict.Custom)
        {
            _log.Warn("engine", verdict.Message);
        }

        AppPaths.EnsureCreated();

        // One directory per session, owner-only, so two runs cannot share a file and a
        // stale one is obvious. The configuration is written, the core reads it, and it
        // is shredded the moment the local port answers - see ShredConfig below.
        string sessionDirectory = Path.Combine(AppPaths.RuntimeDirectory, "session-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(sessionDirectory);
        WindowsAcl.RestrictToCurrentUser(sessionDirectory);
        SecretShredder.RestrictToOwner(sessionDirectory, directory: true);

        _configPath = Path.Combine(sessionDirectory, "config.json");
        await File.WriteAllTextAsync(_configPath, configJson, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        WindowsAcl.RestrictToCurrentUser(_configPath);
        SecretShredder.RestrictToOwner(_configPath, directory: false);
        ProcessStartInfo processStartInfo = new ProcessStartInfo
        {
            FileName = engine,
            WorkingDirectory = Path.GetDirectoryName(engine),
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        processStartInfo.ArgumentList.Add("run");
        processStartInfo.ArgumentList.Add("-c");
        processStartInfo.ArgumentList.Add(_configPath);
        _stopping = false;
        Process process = new Process
        {
            StartInfo = processStartInfo,
            EnableRaisingEvents = true
        };
        process.OutputDataReceived += delegate (object _, DataReceivedEventArgs e)
        {
            PumpLine(e.Data);
        };
        process.ErrorDataReceived += delegate (object _, DataReceivedEventArgs e)
        {
            PumpLine(e.Data);
        };
        process.Exited += OnProcessExited;
        lock (_gate)
        {
            _process = process;
        }
        _log.Info("engine", $"Starting {Path.GetFileName(engine)} (SOCKS 127.0.0.1:{socksPort}, HTTP 127.0.0.1:{httpPort}).");
        if (!process.Start())
        {
            throw new EngineException("The tunnel engine could not be started.");
        }
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        if (!(await WaitForPortAsync(socksPort, process, TimeSpan.FromSeconds(12.0), cancellationToken).ConfigureAwait(continueOnCapturedContext: false)))
        {
            string text = (process.HasExited ? $"the core exited with code {process.ExitCode}" : "the local port never opened");
            Stop();
            throw new EngineException("The tunnel did not come up: " + text + ". See the log for the core's own message.");
        }
        // The core has parsed its configuration; nothing reads the file again.
        ShredConfig();
        _log.Info("engine", "Local endpoints are listening. Tunnel is up.");
    }

    private static async Task<bool> WaitForPortAsync(int port, Process process, TimeSpan timeout, CancellationToken ct)
    {
        DateTime deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            if (process.HasExited)
            {
                return false;
            }
            try
            {
                using TcpClient client = new TcpClient();
                using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(300);
                await client.ConnectAsync("127.0.0.1", port, cts.Token).ConfigureAwait(continueOnCapturedContext: false);
                if (client.Connected)
                {
                    return true;
                }
            }
            catch (SocketException)
            {
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
            }
            await Task.Delay(120, ct).ConfigureAwait(continueOnCapturedContext: false);
        }
        return false;
    }

    private void PumpLine(string? line)
    {
        if (!string.IsNullOrWhiteSpace(line))
        {
            LogLevel level = ((line.Contains("failed", StringComparison.OrdinalIgnoreCase) || line.Contains("error", StringComparison.OrdinalIgnoreCase)) ? LogLevel.Warn : LogLevel.Debug);
            _log.Add(level, "core", line);
        }
    }

    private void OnProcessExited(object? sender, EventArgs e)
    {
        int num;
        try
        {
            num = (sender as Process)?.ExitCode ?? (-1);
        }
        catch (InvalidOperationException)
        {
            num = -1;
        }
        CleanUpConfig();
        if (!_stopping)
        {
            _log.Warn("engine", $"The tunnel core exited unexpectedly (code {num}).");
            this.CoreExited?.Invoke(this, num);
        }
        lock (_gate)
        {
            _process?.Dispose();
            _process = null;
        }
    }

    public void Stop()
    {
        _stopping = true;
        Process? process;
        lock (_gate)
        {
            process = _process;
        }
        if (process != null)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    process.WaitForExit(4000);
                }
            }
            catch (Exception ex) when (((ex is InvalidOperationException || ex is Win32Exception) ? 1 : 0) != 0)
            {
            }
            finally
            {
                process.Dispose();
            }
        }
        lock (_gate)
        {
            _process = null;
        }
        CleanUpConfig();
        _log.Info("engine", "Tunnel core stopped.");
    }

    private void CleanUpConfig()
    {
        string? configPath = _configPath;
        _configPath = null;
        if (configPath is null)
        {
            return;
        }

        ShredConfigPath(configPath);
    }

    /// <summary>Shreds the generated config and its session directory if it is still there.</summary>
    private void ShredConfig()
    {
        string? configPath = _configPath;
        _configPath = null;
        if (configPath is null)
        {
            return;
        }

        ShredConfigPath(configPath);
        _log.Debug("engine", "The generated engine config was shredded; the core holds it in memory only.");
    }

    private static void ShredConfigPath(string configPath)
    {
        SecretShredder.ShredFile(configPath);
        string? directory = Path.GetDirectoryName(configPath);
        if (!string.IsNullOrEmpty(directory) && Directory.Exists(directory))
        {
            SecretShredder.ShredDirectory(directory);
        }
    }

    /// <summary>
    /// Clears runtime files a killed session left behind. Called once at startup, before
    /// a new session writes anything.
    /// </summary>
    public int SweepStaleRuntimeFiles(LogService log)
    {
        int removed = SecretShredder.SweepStale(AppPaths.RuntimeDirectory, TimeSpan.FromHours(1));
        if (removed > 0)
        {
            log.Warn("engine", $"Removed {removed} leftover runtime file(s) from an earlier session that did not exit cleanly.");
        }

        return removed;
    }

    public bool TryGetTraffic(out long bytesIn, out long bytesOut)
    {
        bytesIn = 0L;
        bytesOut = 0L;
        Process? process;
        lock (_gate)
        {
            process = _process;
        }
        if (process == null)
        {
            return false;
        }
        try
        {
            if (!process.HasExited && GetProcessIoCounters(process.Handle, out var ioCounters))
            {
                bytesIn = (long)ioCounters.ReadTransferCount;
                bytesOut = (long)ioCounters.WriteTransferCount;
                return true;
            }
        }
        catch (Exception ex) when (((ex is InvalidOperationException || ex is Win32Exception) ? 1 : 0) != 0)
        {
        }
        return false;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessIoCounters(nint processHandle, out IoCounters ioCounters);

    public void Dispose()
    {
        Stop();
    }
}
