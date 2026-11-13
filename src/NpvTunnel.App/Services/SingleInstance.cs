using System;
using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NpvTunnel.App.Services;

public sealed class SingleInstance : IDisposable
{
    private readonly string _mutexName;

    private readonly string _pipeName;

    private Mutex? _mutex;

    private CancellationTokenSource? _cts;

    private Task? _server;

    public bool IsPrimary { get; private set; }

    public event Action<string>? FileReceived;

    public SingleInstance()
    {
        string text = UserScope();
        _mutexName = "Local\\NpvTunnel.Desktop." + text;
        _pipeName = "npvtunnel-" + text;
    }

    public bool TryAcquire()
    {
        _mutex = new Mutex(initiallyOwned: true, _mutexName, out var createdNew);
        IsPrimary = createdNew;
        return createdNew;
    }

    public bool TrySendToPrimary(string path, TimeSpan timeout)
    {
        try
        {
            using NamedPipeClientStream namedPipeClientStream = new NamedPipeClientStream(".", _pipeName, PipeDirection.Out, PipeOptions.CurrentUserOnly);
            namedPipeClientStream.Connect((int)timeout.TotalMilliseconds);
            using StreamWriter streamWriter = new StreamWriter(namedPipeClientStream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            streamWriter.WriteLine(path);
            streamWriter.Flush();
            return true;
        }
        catch (Exception ex) when (((ex is TimeoutException || ex is IOException || ex is UnauthorizedAccessException) ? 1 : 0) != 0)
        {
            return false;
        }
    }

    public void StartServer()
    {
        if (IsPrimary)
        {
            _cts = new CancellationTokenSource();
            _server = Task.Run(() => ListenAsync(_cts.Token));
        }
    }

    private async Task ListenAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                NamedPipeServerStream server = new NamedPipeServerStream(_pipeName, PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                try
                {
                    await server.WaitForConnectionAsync(ct).ConfigureAwait(continueOnCapturedContext: false);
                    using StreamReader reader = new StreamReader(server, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
                    string text = await reader.ReadLineAsync(ct).ConfigureAwait(continueOnCapturedContext: false);
                    if (!string.IsNullOrWhiteSpace(text) && text.Length < 4096 && File.Exists(text))
                    {
                        this.FileReceived?.Invoke(text);
                    }
                }
                finally
                {
                    if (server != null)
                    {
                        await server.DisposeAsync();
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex2) when (((ex2 is IOException || ex2 is UnauthorizedAccessException) ? 1 : 0) != 0)
            {
                await Task.Delay(250, ct).ConfigureAwait(continueOnCapturedContext: false);
            }
        }
    }

    private static string UserScope()
    {
        try
        {
            string s = WindowsIdentity.GetCurrent().User?.Value ?? Environment.UserName;
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).Substring(0, 16).ToLowerInvariant();
        }
        catch (Exception)
        {
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Environment.UserName))).Substring(0, 16).ToLowerInvariant();
        }
    }

    public void Dispose()
    {
        try
        {
            _cts?.Cancel();
            _server?.Wait(500);
        }
        catch (AggregateException)
        {
        }
        _cts?.Dispose();
        if (IsPrimary)
        {
            try
            {
                _mutex?.ReleaseMutex();
            }
            catch (ApplicationException)
            {
            }
        }
        _mutex?.Dispose();
    }
}
