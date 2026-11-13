using System;
using System.Collections.Generic;
using NpvTunnel.Core.Models;
using NpvTunnel.Core.Security;

namespace NpvTunnel.Core.Import;

public sealed class ImportResult
{
    public Profile? Profile { get; init; }

    public ImportError Error { get; init; }

    public string Message { get; init; } = string.Empty;


    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();


    public bool Success
    {
        get
        {
            if (Error == ImportError.None)
            {
                return Profile != null;
            }
            return false;
        }
    }

    public static ImportResult Ok(Profile profile, params string[] warnings)
    {
        return new ImportResult
        {
            Profile = profile,
            Warnings = warnings
        };
    }

    public static ImportResult Fail(ImportError error, string message)
    {
        return new ImportResult
        {
            Error = error,
            Message = Redactor.Scrub(message)
        };
    }
}
