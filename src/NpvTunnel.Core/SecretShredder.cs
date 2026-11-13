using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace NpvTunnel.Core.Security;

/// <summary>
/// Disposal for files that carry live credentials - the engine configuration above
/// all, since it holds the UUID or password the tunnel authenticates with.
///
/// Overwriting before unlinking does not make a file unrecoverable on a copy-on-write
/// or journalling filesystem, and it is not claimed to. It does mean a plain
/// <c>cat</c>, a backup agent or a support paste cannot read a leftover, and it keeps
/// the window in which the file exists as short as the engine allows.
/// </summary>
public static class SecretShredder
{
    private const int ChunkSize = 81920;

    /// <summary>Overwrites the bytes with random data, flushes, then deletes the file.</summary>
    public static bool ShredFile(string path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            return false;
        }

        try
        {
            long length = new FileInfo(path).Length;
            if (length > 0)
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None, ChunkSize, FileOptions.WriteThrough);
                byte[] buffer = new byte[(int)Math.Min(length, ChunkSize)];
                long remaining = length;
                while (remaining > 0)
                {
                    int take = (int)Math.Min(buffer.Length, remaining);
                    RandomNumberGenerator.Fill(buffer.AsSpan(0, take));
                    stream.Write(buffer, 0, take);
                    remaining -= take;
                }

                stream.Flush(flushToDisk: true);
            }

            File.Delete(path);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Shreds every file in a directory, then removes it.</summary>
    public static bool ShredDirectory(string directory)
    {
        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
        {
            return false;
        }

        try
        {
            foreach (string file in Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories))
            {
                ShredFile(file);
            }

            Directory.Delete(directory, recursive: true);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Removes runtime files left behind by a session that was killed rather than closed.
    /// Called at startup, before a new session writes anything.
    /// </summary>
    public static int SweepStale(string runtimeDirectory, TimeSpan olderThan)
    {
        if (string.IsNullOrEmpty(runtimeDirectory) || !Directory.Exists(runtimeDirectory))
        {
            return 0;
        }

        int removed = 0;
        DateTime cutoff = DateTime.UtcNow - olderThan;
        try
        {
            foreach (string entry in Directory.EnumerateFileSystemEntries(runtimeDirectory))
            {
                DateTime stamp;
                try
                {
                    stamp = Directory.Exists(entry) ? Directory.GetLastWriteTimeUtc(entry) : File.GetLastWriteTimeUtc(entry);
                }
                catch (IOException)
                {
                    continue;
                }

                if (stamp > cutoff)
                {
                    continue;
                }

                if (Directory.Exists(entry) ? ShredDirectory(entry) : ShredFile(entry))
                {
                    removed++;
                }
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }

        return removed;
    }

    /// <summary>Owner-only permissions on Unix; a no-op elsewhere (Windows uses an ACL instead).</summary>
    public static void RestrictToOwner(string path, bool directory)
    {
        if (OperatingSystem.IsWindows() || !File.Exists(path) && !Directory.Exists(path))
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(path, directory
                ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                : UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    /// <summary>The list of files a runtime directory currently holds, for diagnostics.</summary>
    public static IReadOnlyList<string> ListRuntimeFiles(string runtimeDirectory) =>
        Directory.Exists(runtimeDirectory)
            ? new List<string>(Directory.EnumerateFileSystemEntries(runtimeDirectory))
            : Array.Empty<string>();
}
