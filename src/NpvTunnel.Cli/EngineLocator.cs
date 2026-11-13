using System;
using System.IO;

namespace NpvTunnel.Cli;

/// <summary>Finds the engine that ships next to the binary, or one on PATH.</summary>
public static class EngineLocator
{
    public static string? Find()
    {
        string baseDirectory = AppContext.BaseDirectory;
        string[] candidates =
        {
            Path.Combine(baseDirectory, "core", "xray"),
            Path.Combine(baseDirectory, "xray"),
            "/usr/local/lib/npvtunnel/xray",
            "/usr/lib/npvtunnel/xray",
            "/usr/local/bin/xray",
            "/usr/bin/xray",
        };

        foreach (string candidate in candidates)
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        string? path = Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrEmpty(path))
        {
            foreach (string directory in path.Split(Path.PathSeparator))
            {
                string candidate = Path.Combine(directory, "xray");
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }

        return null;
    }
}
