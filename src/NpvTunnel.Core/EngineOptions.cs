using System;
using NpvTunnel.Core.Security;

namespace NpvTunnel.Core.Engine;

public sealed class EngineOptions
{
	public int SocksPort { get; set; } = 2080;


	public int HttpPort { get; set; } = 2081;


	public bool LocalOnly { get; set; } = true;


	public bool BlockIpv6 { get; set; } = true;


	public bool BypassLan { get; set; } = true;


	public bool BlockQuic { get; set; }

	public bool BlockBitTorrent { get; set; }

	public string LogLevel { get; set; } = "warning";


	public string DnsServer { get; set; } = "https+local://1.1.1.1/dns-query";


	public bool EnableMux { get; set; }

	public void Validate()
	{
		if (!Validators.IsUsableLocalPort(SocksPort) || !Validators.IsUsableLocalPort(HttpPort))
		{
			throw new ArgumentException("Local proxy ports must be between 1024 and 65535.");
		}
		if (SocksPort == HttpPort)
		{
			throw new ArgumentException("The SOCKS and HTTP ports must differ.");
		}
	}
}
