using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using NpvTunnel.Core.Models;
using NpvTunnel.Core.Security;
using NpvTunnel.Core.Util;

namespace NpvTunnel.Core.Import;

public static class NpvtImporter
{
    public const int MaxFileBytes = 1048576;

    public static readonly string[] FileExtensions = new string[7] { ".npvt", ".npv", ".npv4", ".inpv", ".json", ".txt", ".conf" };

    public static bool IsSupportedExtension(string path)
    {
        string extension = Path.GetExtension(path);
        return FileExtensions.Contains<string>(extension, StringComparer.OrdinalIgnoreCase);
    }

    public static ImportResult ImportFile(string path, string? password = null)
    {
        try
        {
            FileInfo fileInfo = new FileInfo(path);
            if (!fileInfo.Exists)
            {
                return ImportResult.Fail(ImportError.UnknownFormat, "The file does not exist.");
            }
            if (fileInfo.Length > 1048576)
            {
                return ImportResult.Fail(ImportError.TooLarge, $"The file is {fileInfo.Length / 1024} KiB; the limit is {1024} KiB.");
            }
            return ImportText(File.ReadAllText(path), password, Path.GetFileName(path));
        }
        catch (IOException ex)
        {
            return ImportResult.Fail(ImportError.UnknownFormat, "The file could not be read: " + ex.Message);
        }
        catch (UnauthorizedAccessException)
        {
            return ImportResult.Fail(ImportError.UnknownFormat, "Access to the file was denied.");
        }
    }

    public static ImportResult ImportText(string text, string? password = null, string source = "")
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return ImportResult.Fail(ImportError.Empty, "The configuration is empty.");
        }
        if (text.Length > 2097152)
        {
            return ImportResult.Fail(ImportError.TooLarge, "The configuration is too large.");
        }
        string text2 = text.Trim();
        if (LockedConfig.IsEnvelope(text2))
        {
            if (string.IsNullOrEmpty(password))
            {
                return ImportResult.Fail(ImportError.EncryptedNeedsPassword, "This .npvt file is locked. Enter the passphrase provided by the config author.");
            }
            string? text3 = LockedConfig.TryUnlock(text2, password);
            if (text3 == null)
            {
                return ImportResult.Fail(ImportError.BadPassword, "Wrong passphrase, or the file is corrupted.");
            }
            ImportResult importResult = ImportText(text3, null, source);
            if (!importResult.Success)
            {
                return importResult;
            }
            return AttachSource(importResult, source);
        }
        // The vendor's own containers: "NPVT1" + comma-separated encrypted blocks.
        if (NpvtContainer.Identify(text2) == NpvtContainer.ContainerKind.Npvt)
        {
            ImportBatch containerBatch = ImportAll(text2, password, source);
            ImportResult? first = containerBatch.Results.FirstOrDefault((ImportResult r) => r.Success) ?? containerBatch.Results.FirstOrDefault();
            if (first != null)
            {
                return first;
            }
            return ImportResult.Fail(containerBatch.Error == ImportError.None ? ImportError.UnknownFormat : containerBatch.Error, containerBatch.Message);
        }
        if (NpvtContainer.Identify(text2) == NpvtContainer.ContainerKind.Npvs)
        {
            return ImportResult.Fail(ImportError.LegacyEncryptedConfig, NpvtContainer.ExplainUnsupported(text2));
        }
        if (UriParser.LooksLikeUri(text2))
        {
            ImportResult importResult2 = UriParser.Parse(text2);
            if (!importResult2.Success)
            {
                return importResult2;
            }
            return AttachSource(importResult2, source);
        }
        if (text2.StartsWith('{') || text2.StartsWith('['))
        {
            return ParseJson(text2, source);
        }
        int length = text2.Length;
        if (length > 16 && length < 700000 && text2.All(IsBase64Char) && Base64Url.TryDecodeUtf8(text2, out string decoded))
        {
            string text4 = decoded.Trim();
            if (text4.StartsWith('{') || text4.StartsWith('[') || UriParser.LooksLikeUri(text4))
            {
                ImportResult importResult3 = ImportText(text4, password, source);
                if (!importResult3.Success)
                {
                    return importResult3;
                }
                return AttachSource(importResult3, source);
            }
        }
        if (LooksLikeLegacyBlob(text2))
        {
            return ImportResult.Fail(ImportError.LegacyEncryptedConfig, "This looks like a legacy encrypted NPV blob (.npv / .npv4 / .inpv). It is encrypted with a closed, proprietary format that only the vendor's mobile app can read, so importing it would mean shipping their binary parser. Ask the provider for an open .npvt (npvt/1) file or a share link instead.");
        }
        return ImportResult.Fail(ImportError.UnknownFormat, "Unrecognised configuration. Supported inputs: NPV Tunnel .npvt containers, vless/vmess/trojan/ss/socks/http/hysteria2 share links, and npvt/1 JSON documents.");
    }

    public static bool IsJsonDocument(string text)
    {
        return text.TrimStart().StartsWith('{');
    }

    public static ImportResult FromProfile(Profile profile, string source)
    {
        return Validate(profile, new List<string>(), source);
    }

    private static ImportResult ParseJson(string text, string source)
    {
        JsonDocument jsonDocument;
        try
        {
            jsonDocument = SafeJson.Parse(text);
        }
        catch (SafeJson.JsonTooLargeException ex)
        {
            return ImportResult.Fail(ImportError.TooLarge, ex.Message);
        }
        catch (SafeJson.JsonStructureException ex2)
        {
            return ImportResult.Fail(ImportError.InvalidField, "Rejected configuration: " + ex2.Message);
        }
        catch (JsonException ex3)
        {
            return ImportResult.Fail(ImportError.UnknownFormat, "The JSON is not valid: " + ex3.Message);
        }
        using (jsonDocument)
        {
            JsonElement rootElement = jsonDocument.RootElement;
            if (rootElement.ValueKind != JsonValueKind.Object)
            {
                return ImportResult.Fail(ImportError.UnknownFormat, "The document root must be a JSON object.");
            }
            if (rootElement.TryGetProperty("outbounds", out var value) || rootElement.TryGetProperty("inbounds", out value))
            {
                return ImportResult.Fail(ImportError.UnknownFormat, "This is a full Xray/V2Ray client config, not an npvt profile. Share links and npvt/1 documents are supported; a raw client config would be able to run arbitrary core features.");
            }
            JsonElement value2;
            string? text2 = ((rootElement.TryGetProperty("schema", out value2) && value2.ValueKind == JsonValueKind.String) ? value2.GetString() : null);
            if (text2 != null && !text2.StartsWith("npvt/", StringComparison.OrdinalIgnoreCase))
            {
                return ImportResult.Fail(ImportError.UnknownFormat, "Unknown schema '" + text2 + "'.");
            }
            NpvtDocument npvtDocument;
            try
            {
                npvtDocument = JsonSerializer.Deserialize<NpvtDocument>(text) ?? new NpvtDocument();
            }
            catch (JsonException ex4)
            {
                return ImportResult.Fail(ImportError.InvalidField, "The npvt document is malformed: " + ex4.Message);
            }
            Profile profile = npvtDocument.ToProfile();
            List<string> list = new List<string>();
            if (!string.IsNullOrWhiteSpace(npvtDocument.Remarks))
            {
                list.Add("Note from the config author: " + Redactor.Scrub(npvtDocument.Remarks));
            }
            if (npvtDocument.AllowInsecure)
            {
                profile.AllowInsecure = false;
                list.Add("This config asked to skip TLS verification. That was ignored; enable it in Settings only if you trust the server.");
            }
            return Validate(profile, list, source);
        }
    }

    internal static ImportResult Validate(Profile profile, List<string> warnings, string source)
    {
        if (string.IsNullOrWhiteSpace(profile.Address) || !Validators.IsSafeHost(profile.Address))
        {
            return ImportResult.Fail(ImportError.InvalidField, "The server address is missing or invalid.");
        }
        int port = profile.Port;
        if (port < 1 || port > 65535)
        {
            return ImportResult.Fail(ImportError.InvalidField, "The port is out of range.");
        }
        if (!Validators.IsSafePath(profile.Path))
        {
            return ImportResult.Fail(ImportError.InvalidField, "The transport path contains unsupported characters.");
        }
        if (!Validators.IsValidShortId(profile.ShortId))
        {
            return ImportResult.Fail(ImportError.InvalidField, "The REALITY short id must be hex (max 16 chars).");
        }
        if (profile.Security == SecurityLayer.Reality && !Validators.IsValidRealityKey(profile.PublicKey))
        {
            return ImportResult.Fail(ImportError.InvalidField, "The REALITY public key is not a valid x25519 key.");
        }
        profile.Source = source;
        return ImportResult.Ok(profile, warnings.ToArray());
    }

    private static ImportResult AttachSource(ImportResult result, string source)
    {
        if (result.Profile != null)
        {
            result.Profile.Source = source;
        }
        return result;
    }

    private static bool IsBase64Char(char c)
    {
        bool flag = char.IsAsciiLetterOrDigit(c);
        if (!flag)
        {
            bool flag2;
            switch (c)
            {
                case '+':
                case '-':
                case '/':
                case '=':
                case '_':
                    flag2 = true;
                    break;
                default:
                    flag2 = false;
                    break;
            }
            flag = flag2;
        }
        return flag;
    }

    /// <summary>
    /// Imports everything in <paramref name="text"/>: a vendor .npvt container with
    /// dozens of profiles, a JSON array, a share link or an npvt/1 document.
    /// </summary>
    public static ImportBatch ImportAll(string text, string? password = null, string source = "")
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return new ImportBatch { Error = ImportError.Empty, Message = "The configuration is empty." };
        }

        string trimmed = text.Trim();

        if (NpvtContainer.Identify(trimmed) == NpvtContainer.ContainerKind.Npvs)
        {
            return new ImportBatch
            {
                Error = ImportError.LegacyEncryptedConfig,
                Message = NpvtContainer.ExplainUnsupported(trimmed)
            };
        }

        if (NpvtContainer.Identify(trimmed) != NpvtContainer.ContainerKind.Npvt)
        {
            ImportResult single = ImportText(trimmed, password, source);
            return new ImportBatch
            {
                Results = new[] { single },
                Error = single.Success ? ImportError.None : single.Error,
                Message = single.Success ? string.Empty : single.Message
            };
        }

        if (!NpvtContainer.TryDecrypt(trimmed, out IReadOnlyList<string> payloads, out string decryptError))
        {
            return new ImportBatch { Error = ImportError.UnknownFormat, Message = decryptError };
        }

        var results = new List<ImportResult>();
        var batchWarnings = new List<string>();
        bool sawLockBlock = false;

        foreach (string payload in payloads)
        {
            string block = payload.Trim();
            if (block.Length == 0)
            {
                continue;
            }

            // The version chunk is literally "1"; the lockConfig chunk is an object
            // without a v2rayProfile. Both are expected and skipped silently.
            if (block.Length <= 8 && !block.StartsWith('{') && !block.StartsWith('['))
            {
                continue;
            }

            if (block.StartsWith('[') || block.StartsWith('{'))
            {
                IReadOnlyList<Profile> profiles = NpvConfigReader.ReadPayload(block, batchWarnings);
                if (profiles.Count == 0)
                {
                    sawLockBlock = true;
                    continue;
                }

                foreach (Profile profile in profiles)
                {
                    var warnings = new List<string>();
                    if (profile.AllowInsecure)
                    {
                        // A channel config may not silently disable certificate checks.
                        profile.AllowInsecure = false;
                        warnings.Add("This configuration asked to skip TLS verification; that request was ignored.");
                    }

                    results.Add(Validate(profile, warnings, source));
                }

                continue;
            }

            if (UriParser.LooksLikeUri(block))
            {
                results.Add(UriParser.Parse(block));
            }
        }

        if (results.Count == 0)
        {
            return new ImportBatch
            {
                Error = ImportError.UnknownFormat,
                Message = sawLockBlock
                    ? "This .npvt container opened, but it holds no server configuration - only the author's lock settings."
                    : "This .npvt container opened, but none of its entries could be read as a configuration.",
                Warnings = batchWarnings
            };
        }

        int failed = results.Count((ImportResult r) => !r.Success);
        string summary = failed == 0 ? string.Empty : failed + " of " + results.Count + " entries were skipped.";
        return new ImportBatch
        {
            Results = results,
            Message = summary,
            Warnings = batchWarnings
        };
    }

    private static bool LooksLikeLegacyBlob(string text)
    {
        if (text.Length > 32)
        {
            return text.All(IsBase64Char);
        }
        return false;
    }
}
