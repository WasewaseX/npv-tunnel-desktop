namespace NpvTunnel.App.Services;

public static class EngineManifest
{
    public const string EngineName = "xray.exe";

    public const string CoreName = "Xray-core";

    public const string Version = "26.11.9";

    public const string ArchiveSha256 = "1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d";

    /// <summary>
    /// Kept as the human-readable record of the Windows pin. The authority is
    /// <see cref="NpvTunnel.Core.Engine.EngineIntegrity.Known"/>; a test compares the two so
    /// one cannot be updated without the other.
    /// </summary>
    public const string PipelineSha256 = "1ca7a2cf61ba2c5d20b21a80d405b57933939751081cb289f07bd8ddf7cc3185";

    public const string ArchiveUrl = "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-windows-64.zip";

    public static readonly string[] AllowedDownloadHosts = new string[3] { "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com" };

    public static readonly string[] ExtractedFiles = new string[4] { "xray.exe", "LICENSE", "geoip.dat", "geosite.dat" };
}
