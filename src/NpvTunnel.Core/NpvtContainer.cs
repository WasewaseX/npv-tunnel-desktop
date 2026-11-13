using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NpvTunnel.Core.Import;

/// <summary>
/// Reader for the containers the mobile app actually ships: <c>.npvt</c> files
/// that begin with <c>NPVT1</c> (or <c>NPVTSUB1</c>) and carry comma-separated
/// base64 blobs, each one a white-box AES-CTR keystream over a 16-byte nonce.
/// </summary>
/// <remarks>
/// This is not the documented "npvt/1" JSON of this project - that is our own
/// open format. These are the vendor's obfuscated containers, and reading them
/// is the whole point of a desktop port: a user who downloads a config from a
/// channel must be able to double-click it.
///
/// The blobs hold, in order: a version chunk ("1"), a JSON array of profile
/// wrappers, and a lockConfig chunk that describes the author's restrictions.
/// </remarks>
public static class NpvtContainer
{
    /// <summary>Every vendor container starts with these three bytes.</summary>
    public const string Magic = "NPV";

    private const int MaxTokenLength = 4 * 1024 * 1024;

    public enum ContainerKind
    {
        None,
        Npvt,
        Npvs,
    }

    /// <summary>Classifies a payload without decrypting anything.</summary>
    public static ContainerKind Identify(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return ContainerKind.None;
        }

        ReadOnlySpan<char> span = text.AsSpan().TrimStart();
        if (span.Length < 4 || !span.StartsWith(Magic, StringComparison.Ordinal))
        {
            return ContainerKind.None;
        }

        return span[3] switch
        {
            'T' => ContainerKind.Npvt,
            'S' => ContainerKind.Npvs,
            _ => ContainerKind.None,
        };
    }

    /// <summary>
    /// Decrypts every blob in an NPVT container. Returns the plaintext payloads in
    /// file order; on failure <paramref name="error"/> explains why in user terms.
    /// </summary>
    public static bool TryDecrypt(string text, out IReadOnlyList<string> payloads, out string error)
    {
        payloads = Array.Empty<string>();
        error = string.Empty;

        if (Identify(text) != ContainerKind.Npvt)
        {
            error = "That is not an NPVT container.";
            return false;
        }

        // The headers are noise once split: "NPVT1\n<x>,<y>,<z>" and the
        // subscription flavour "NPVTSUB1\n<x>" both just separate the blobs.
        string body = text
            .Replace("NPVTSUB1", ",", StringComparison.Ordinal)
            .Replace("NPVT1", ",", StringComparison.Ordinal);

        var results = new List<string>();
        foreach (string rawToken in body.Split(','))
        {
            string token = rawToken.Trim();
            if (token.Length == 0)
            {
                continue;
            }

            if (token.Length > MaxTokenLength)
            {
                error = "The configuration is larger than this app will decode.";
                return false;
            }

            byte[] blob;
            try
            {
                blob = Convert.FromBase64String(token);
            }
            catch (FormatException)
            {
                error = "The container is damaged: one of its blocks is not valid base64.";
                return false;
            }

            string? plain = DecodeBlob(blob);
            if (plain is null)
            {
                error = "This container uses a cipher generation this build does not know.";
                return false;
            }

            if (plain.Length > 0)
            {
                results.Add(plain);
            }
        }

        if (results.Count == 0)
        {
            error = "The container is empty.";
            return false;
        }

        payloads = results;
        return true;
    }

    private static string? DecodeBlob(byte[] blob)
    {
        byte[] plain = NpvtWhitebox.Decrypt(blob);
        if (plain.Length == 0)
        {
            return null;
        }

        // A wrong generation produces bytes that are not UTF-8; refuse rather than
        // hand garbage to the JSON reader.
        try
        {
            var strict = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
            return strict.GetString(plain).TrimEnd('\0');
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }

    /// <summary>Human-readable explanation for a container we cannot open.</summary>
    public static string ExplainUnsupported(string text)
    {
        if (Identify(text) == ContainerKind.Npvs)
        {
            return
                "This is an .npvs container (NPVS envelope), and that format is locked with a key or "
                + "passphrase that only the config author holds. Ask the provider for a .npvt file or a "
                + "share link. Nothing here is silently guessed: this app will not pretend to import a "
                + "config it cannot actually read.";
        }

        return "Unrecognised configuration.";
    }

    internal static bool LooksLikeText(string value) =>
        value.StartsWith('[') || value.StartsWith('{') || value.Contains("://", StringComparison.Ordinal);
}
