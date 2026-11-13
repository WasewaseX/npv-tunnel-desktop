using System;
using NpvTunnel.Core.Import;

namespace NpvTunnel.App.Services;

public sealed class StoredProfile
{
	public Guid Id { get; set; } = Guid.NewGuid();


	public DateTimeOffset ImportedAt { get; set; } = DateTimeOffset.Now;


	public DateTimeOffset? LastConnectedAt { get; set; }

	public long LastPingMs { get; set; }

	public NpvtDocument Document { get; set; } = new NpvtDocument();

}
