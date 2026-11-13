using System;
using System.Collections.Generic;

namespace NpvTunnel.Core.Engine;

public sealed class EngineConfig
{
    public required string Json { get; init; }

    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();

}
