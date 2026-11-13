using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NpvTunnel.Core.Models;

namespace NpvTunnel.Cli;

/// <summary>
/// The Linux profile store. Configs picked up from public channels carry live
/// credentials, so the store is sealed with AES-256-GCM under a key that lives
/// beside it and is readable only by the owner. The file is created 0600 inside a
/// 0700 directory and replaced atomically, so a crash cannot leave a truncated
/// store behind. This is protection at rest, not a replacement for disk
/// encryption: anyone who can read the key can read the profiles.
/// </summary>
public sealed class ProfileStore
{
    private const string EnvelopeFormat = "npvtunnel-sealed";
    private const int EnvelopeVersion = 1;
    private static readonly byte[] AdditionalData = Encoding.ASCII.GetBytes("npvtunnel-sealed-v1");

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
    };

    public ProfileStore(string? overridePath = null)
    {
        FilePath = overridePath ?? DefaultPath();
    }

    public string FilePath { get; }

    /// <summary>Encryption key for the store; created on first save, owner-read only.</summary>
    public string KeyPath => Path.Combine(Path.GetDirectoryName(FilePath) ?? ".", "store.key");

    public static string DefaultPath()
    {
        string baseDir = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        return Path.Combine(baseDir, "npvtunnel", "profiles.json");
    }

    public List<Profile> Load()
    {
        if (!File.Exists(FilePath))
        {
            return new List<Profile>();
        }

        string raw = File.ReadAllText(FilePath);
        try
        {
            if (LooksSealed(raw))
            {
                return JsonSerializer.Deserialize<List<Profile>>(Unseal(raw), SerializerOptions) ?? new List<Profile>();
            }

            // Stores written by 1.0.2 and earlier: plaintext list, migrated on next save.
            return JsonSerializer.Deserialize<List<Profile>>(raw, SerializerOptions) ?? new List<Profile>();
        }
        catch (JsonException)
        {
            throw new InvalidDataException($"The profile store at {FilePath} is not valid JSON.");
        }
        catch (CryptographicException ex)
        {
            throw new InvalidDataException(
                $"The store at {FilePath} cannot be opened with the key beside it. Restore the key from a backup, or delete both files and re-import the configurations.",
                ex);
        }
    }

    public void Save(IEnumerable<Profile> profiles)
    {
        string? directory = Path.GetDirectoryName(FilePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
            TryChmod(directory, "700");
        }

        string json = JsonSerializer.Serialize(profiles.ToList(), SerializerOptions);
        string sealedDocument = Seal(json);

        // Write-then-rename so a crash cannot leave a half-written store.
        string temp = FilePath + ".tmp";
        File.WriteAllText(temp, sealedDocument);
        TryChmod(temp, "600");
        File.Move(temp, FilePath, overwrite: true);
    }

    private static bool LooksSealed(string raw) =>
        raw.TrimStart().StartsWith('{') && raw.Contains("\"" + EnvelopeFormat + "\"", StringComparison.Ordinal);

    private string Seal(string plaintext)
    {
        byte[] key = LoadOrCreateKey();
        byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
        RandomNumberGenerator.Fill(nonce);
        byte[] plain = Encoding.UTF8.GetBytes(plaintext);
        byte[] cipher = new byte[plain.Length];
        byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];

        using (var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize))
        {
            aes.Encrypt(nonce, plain, cipher, tag, AdditionalData);
        }

        byte[] payload = new byte[cipher.Length + tag.Length];
        cipher.CopyTo(payload, 0);
        tag.CopyTo(payload, cipher.Length);

        return JsonSerializer.Serialize(new SealedEnvelope
        {
            Format = EnvelopeFormat,
            Version = EnvelopeVersion,
            Nonce = Convert.ToBase64String(nonce),
            Payload = Convert.ToBase64String(payload),
        }, SerializerOptions);
    }

    private string Unseal(string raw)
    {
        SealedEnvelope? envelope = JsonSerializer.Deserialize<SealedEnvelope>(raw, SerializerOptions);
        if (envelope is null || envelope.Version != EnvelopeVersion)
        {
            throw new InvalidDataException($"The profile store at {FilePath} was written by a newer npvtunnel.");
        }

        byte[] key = LoadOrCreateKey();
        byte[] nonce = Convert.FromBase64String(envelope.Nonce);
        byte[] payload = Convert.FromBase64String(envelope.Payload);
        if (payload.Length <= AesGcm.TagByteSizes.MaxSize)
        {
            throw new InvalidDataException($"The profile store at {FilePath} is truncated.");
        }

        int split = payload.Length - AesGcm.TagByteSizes.MaxSize;
        byte[] cipher = payload[..split];
        byte[] tag = payload[split..];
        byte[] plain = new byte[cipher.Length];

        using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
        aes.Decrypt(nonce, cipher, tag, plain, AdditionalData);
        return Encoding.UTF8.GetString(plain);
    }

    private byte[] LoadOrCreateKey()
    {
        if (File.Exists(KeyPath))
        {
            byte[] existing = File.ReadAllBytes(KeyPath);
            if (existing.Length == 32)
            {
                return existing;
            }

            throw new InvalidDataException($"The store key at {KeyPath} is damaged (expected 32 bytes, found {existing.Length}).");
        }

        byte[] key = RandomNumberGenerator.GetBytes(32);
        string? directory = Path.GetDirectoryName(KeyPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
            TryChmod(directory, "700");
        }

        // Create-new so two processes never race to different keys.
        try
        {
            using var stream = new FileStream(KeyPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            stream.Write(key, 0, key.Length);
            stream.Flush(flushToDisk: true);
            TryChmod(KeyPath, "600");
        }
        catch (IOException) when (File.Exists(KeyPath))
        {
            byte[] winner = File.ReadAllBytes(KeyPath);
            if (winner.Length == 32)
            {
                return winner;
            }

            throw;
        }

        return key;
    }

    private static void TryChmod(string path, string mode)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(path, mode == "700"
                ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                : UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (IOException)
        {
            // Filesystems without unix permissions: not fatal, but worth knowing.
        }
    }

    private sealed class SealedEnvelope
    {
        public string Format { get; set; } = EnvelopeFormat;

        public int Version { get; set; }

        public string Nonce { get; set; } = string.Empty;

        public string Payload { get; set; } = string.Empty;
    }
}
