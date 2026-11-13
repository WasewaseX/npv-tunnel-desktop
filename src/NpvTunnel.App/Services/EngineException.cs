using System;

namespace NpvTunnel.App.Services;

public sealed class EngineException : Exception
{
	public EngineException(string message)
		: base(message)
	{
	}
}
