using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using NpvTunnel.Core.Security;

namespace NpvTunnel.App.Services;

public static class PingService
{
	public static async Task<long> MeasureAsync(string host, int port, TimeSpan timeout, CancellationToken ct)
	{
		if (!Validators.IsSafeHost(host))
		{
			return -1L;
		}
		Stopwatch stopwatch = Stopwatch.StartNew();
		try
		{
			using TcpClient client = new TcpClient();
			using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
			cts.CancelAfter(timeout);
			await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(continueOnCapturedContext: false);
			stopwatch.Stop();
			return client.Connected ? stopwatch.ElapsedMilliseconds : (-1);
		}
		catch (Exception ex) when (((ex is SocketException || ex is OperationCanceledException || ex is ArgumentException) ? 1 : 0) != 0)
		{
			return -1L;
		}
	}
}
