using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NpvTunnel.App.Services;

public sealed class AppSettings
{
    private static readonly JsonSerializerOptions Options = new JsonSerializerOptions
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    public bool SetSystemProxy { get; set; } = true;


    public bool BlockIpv6 { get; set; } = true;


    public bool BlockQuic { get; set; } = true;


    public bool BypassLan { get; set; } = true;


    public bool BlockBitTorrent { get; set; }

    public int SocksPort { get; set; } = 2080;


    public int HttpPort { get; set; } = 2081;


    public string DnsServer { get; set; } = "https+local://1.1.1.1/dns-query";


    public string LogLevel { get; set; } = "warning";


    public bool AutoReconnect { get; set; } = true;


    public bool AllowInsecureTls { get; set; }

    public bool StartWithWindows { get; set; }

    public bool MinimizeToTrayHintShown { get; set; }

    public string CustomEnginePath { get; set; } = string.Empty;


    public Guid? ActiveProfileId { get; set; }

    public bool FileAssociationOffered { get; set; }

    [JsonIgnore]
    public string FilePath => AppPaths.SettingsFile;

    public static AppSettings Load()
    {
        try
        {
            AppPaths.EnsureCreated();
            if (!File.Exists(AppPaths.SettingsFile))
            {
                return new AppSettings();
            }
            return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(AppPaths.SettingsFile), Options) ?? new AppSettings();
        }
        catch (Exception ex) when (((ex is IOException || ex is JsonException || ex is UnauthorizedAccessException) ? 1 : 0) != 0)
        {
            return new AppSettings();
        }
    }

    public void Save()
    {
        try
        {
            AppPaths.EnsureCreated();
            string text = AppPaths.SettingsFile + ".tmp";
            File.WriteAllText(text, JsonSerializer.Serialize(this, Options));
            File.Move(text, AppPaths.SettingsFile, overwrite: true);
        }
        catch (Exception ex) when (((ex is IOException || ex is UnauthorizedAccessException) ? 1 : 0) != 0)
        {
        }
    }
}
