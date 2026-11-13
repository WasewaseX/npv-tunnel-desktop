using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NpvTunnel.Core.Models;

namespace NpvTunnel.Core.Import;

/// <summary>
/// The result of importing one source that may contain many configurations - a
/// vendor <c>.npvt</c> container from a channel usually holds ten to fifty.
/// </summary>
public sealed class ImportBatch
{
    public IReadOnlyList<ImportResult> Results { get; init; } = Array.Empty<ImportResult>();

    /// <summary>Fatal error code, set only when nothing at all could be imported.</summary>
    public ImportError Error { get; init; }

    /// <summary>Explanation for the user; empty when every profile imported cleanly.</summary>
    public string Message { get; init; } = string.Empty;

    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();

    public IReadOnlyList<Profile> Profiles =>
        Results.Where(r => r.Success).Select(r => r.Profile!).ToList();

    public int ImportedCount => Profiles.Count;

    public int FailedCount => Results.Count(r => !r.Success);

    public bool Success => ImportedCount > 0;
}
