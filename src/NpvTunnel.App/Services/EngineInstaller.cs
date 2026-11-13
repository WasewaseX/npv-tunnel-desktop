using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace NpvTunnel.App.Services;

public static class EngineInstaller
{
    private const long MaxArchiveBytes = 100663296L;

    public static async Task<string> DownloadAndInstallAsync(IProgress<double>? progress, LogService log, CancellationToken ct)
    {
        string targetDirectory = Path.Combine(AppPaths.InstallDirectory, "core");
        Directory.CreateDirectory(targetDirectory);
        using HttpClientHandler handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseProxy = true
        };
        using HttpClient client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromMinutes(5.0)
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("NpvTunnel-Desktop/1.0");
        byte[] array = await DownloadAsync(client, "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-windows-64.zip", progress, ct).ConfigureAwait(continueOnCapturedContext: false);
        string text = Convert.ToHexString(SHA256.HashData(array));
        if (!text.Equals("1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d", StringComparison.OrdinalIgnoreCase))
        {
            log.Error("engine", "Engine download failed its SHA-256 check and was discarded.");
            throw new EngineException("The downloaded engine does not match the pinned digest. Nothing was installed.");
        }
        log.Info("engine", "Engine archive verified (sha256 " + text.Substring(0, 16) + "…), extracting.");
        string temporary = Path.Combine(targetDirectory, "extract-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temporary);
        try
        {
            using ZipArchive zip = new ZipArchive(new MemoryStream(array), ZipArchiveMode.Read);
            foreach (ZipArchiveEntry entry in zip.Entries)
            {
                string fileName = Path.GetFileName(entry.FullName);
                if (EngineManifest.ExtractedFiles.Contains<string>(fileName, StringComparer.OrdinalIgnoreCase))
                {
                    string text2 = Path.Combine(temporary, fileName);
                    if (Path.GetFullPath(text2).StartsWith(Path.GetFullPath(temporary), StringComparison.OrdinalIgnoreCase))
                    {
                        entry.ExtractToFile(text2, overwrite: true);
                    }
                }
            }
            string path = Path.Combine(temporary, "xray.exe");
            if (!File.Exists(path))
            {
                throw new EngineException("The archive did not contain the engine binary.");
            }
            if (!Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path, ct).ConfigureAwait(continueOnCapturedContext: false))).Equals("1ca7a2cf61ba2c5d20b21a80d405b57933939751081cb289f07bd8ddf7cc3185", StringComparison.OrdinalIgnoreCase))
            {
                throw new EngineException("The extracted engine does not match the pinned digest.");
            }
            string[] extractedFiles = EngineManifest.ExtractedFiles;
            foreach (string path2 in extractedFiles)
            {
                string text3 = Path.Combine(temporary, path2);
                if (File.Exists(text3))
                {
                    File.Move(text3, Path.Combine(targetDirectory, path2), overwrite: true);
                }
            }
            await File.WriteAllTextAsync(Path.Combine(targetDirectory, "ENGINE.sha256"), "1ca7a2cf61ba2c5d20b21a80d405b57933939751081cb289f07bd8ddf7cc3185  xray.exe" + Environment.NewLine, ct).ConfigureAwait(continueOnCapturedContext: false);
        }
        finally
        {
            try
            {
                Directory.Delete(temporary, recursive: true);
            }
            catch (IOException)
            {
            }
        }
        log.Info("engine", $"Installed {"Xray-core"} {"26.11.9"} into {targetDirectory}.");
        return Path.Combine(targetDirectory, "xray.exe");
    }

    private static async Task<byte[]> DownloadAsync(HttpClient client, string url, IProgress<double>? progress, CancellationToken ct)
    {
        string uriString = url;
        for (int hop = 0; hop < 6; hop++)
        {
            Uri uri = new Uri(uriString);
            if (uri.Scheme != Uri.UriSchemeHttps || !EngineManifest.AllowedDownloadHosts.Contains<string>(uri.Host, StringComparer.OrdinalIgnoreCase))
            {
                throw new EngineException("Refusing to download from " + uri.Host + ".");
            }
            using HttpResponseMessage response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(continueOnCapturedContext: false);
            int statusCode = (int)response.StatusCode;
            if (statusCode >= 300 && statusCode < 400)
            {
                Uri uri2 = response.Headers.Location ?? throw new EngineException("The download redirect had no target.");
                uriString = (uri2.IsAbsoluteUri ? uri2.ToString() : new Uri(uri, uri2).ToString());
                continue;
            }
            response.EnsureSuccessStatusCode();
            long? declared = response.Content.Headers.ContentLength;
            if (declared > 100663296)
            {
                throw new EngineException("The engine archive is unexpectedly large.");
            }
            Stream source = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(continueOnCapturedContext: false);
            byte[] result;
            try
            {
                using MemoryStream buffer = new MemoryStream();
                byte[] chunk = new byte[81920];
                long total = 0L;
                int num;
                while ((num = await source.ReadAsync(chunk, ct).ConfigureAwait(continueOnCapturedContext: false)) > 0)
                {
                    total += num;
                    if (total > 100663296)
                    {
                        throw new EngineException("The engine archive exceeded the size limit.");
                    }
                    buffer.Write(chunk, 0, num);
                    if (declared.HasValue && declared.GetValueOrDefault() > 0)
                    {
                        progress?.Report((double)total / (double)declared.Value);
                    }
                }
                result = buffer.ToArray();
            }
            finally
            {
                if (source != null)
                {
                    await source.DisposeAsync();
                }
            }
            return result;
        }
        throw new EngineException("Too many redirects while downloading the engine.");
    }
}
