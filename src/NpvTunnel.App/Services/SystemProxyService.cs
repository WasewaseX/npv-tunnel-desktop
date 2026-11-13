using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text.Json;
using Microsoft.Win32;

namespace NpvTunnel.App.Services;

public sealed class SystemProxyService
{
    public sealed class ProxySnapshot
    {
        public bool HadProxyEnable { get; set; }

        public int ProxyEnable { get; set; }

        public string? ProxyServer { get; set; }

        public string? ProxyOverride { get; set; }

        public bool AutoConfigUrlPresent { get; set; }

        public string? AutoConfigUrl { get; set; }

        public bool Existed { get; set; }
    }

    private const string SettingsKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

    private const string BackupKey = "Software\\NpvTunnel\\ProxyBackup";

    private readonly LogService _log;

    public SystemProxyService(LogService log)
    {
        _log = log;
    }

    public bool IsApplied(out string? server)
    {
        server = null;
        using RegistryKey? registryKey = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", writable: false);
        if (registryKey == null)
        {
            return false;
        }
        bool num2 = registryKey.GetValue("ProxyEnable") is int num && num == 1;
        server = registryKey.GetValue("ProxyServer") as string;
        return num2 && server != null && server.Contains("127.0.0.1", StringComparison.Ordinal);
    }

    public void Apply(int httpPort)
    {
        try
        {
            SaveSnapshot();
            using RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", writable: true) ?? Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", writable: true);
            registryKey.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
            registryKey.SetValue("ProxyServer", $"127.0.0.1:{httpPort}", RegistryValueKind.String);
            registryKey.SetValue("ProxyOverride", "<local>", RegistryValueKind.String);
            registryKey.DeleteValue("AutoConfigURL", throwOnMissingValue: false);
            Refresh();
            _log.Info("proxy", $"System proxy → 127.0.0.1:{httpPort} (previous settings snapshotted).");
        }
        catch (Exception ex) when (((ex is UnauthorizedAccessException || ex is SecurityException || ex is IOException) ? 1 : 0) != 0)
        {
            _log.Warn("proxy", "Could not set the system proxy: " + ex.Message);
        }
    }

    public void Restore()
    {
        try
        {
            using (RegistryKey? registryKey = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", writable: true))
            {
                if (registryKey != null)
                {
                    registryKey.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                    registryKey.DeleteValue("ProxyServer", throwOnMissingValue: false);
                }
            }
            ProxySnapshot? proxySnapshot = LoadSnapshot();
            if (proxySnapshot != null && proxySnapshot.Existed)
            {
                using RegistryKey? registryKey2 = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", writable: true);
                if (registryKey2 != null)
                {
                    registryKey2.SetValue("ProxyEnable", proxySnapshot.ProxyEnable, RegistryValueKind.DWord);
                    if (!string.IsNullOrEmpty(proxySnapshot.ProxyServer))
                    {
                        registryKey2.SetValue("ProxyServer", proxySnapshot.ProxyServer, RegistryValueKind.String);
                    }
                    if (!string.IsNullOrEmpty(proxySnapshot.ProxyOverride))
                    {
                        registryKey2.SetValue("ProxyOverride", proxySnapshot.ProxyOverride, RegistryValueKind.String);
                    }
                    if (proxySnapshot.AutoConfigUrlPresent && !string.IsNullOrEmpty(proxySnapshot.AutoConfigUrl))
                    {
                        registryKey2.SetValue("AutoConfigURL", proxySnapshot.AutoConfigUrl, RegistryValueKind.String);
                    }
                }
            }
            Registry.CurrentUser.DeleteSubKeyTree("Software\\NpvTunnel\\ProxyBackup", throwOnMissingSubKey: false);
            Refresh();
            _log.Info("proxy", "System proxy restored to its previous state.");
        }
        catch (Exception ex) when (((ex is UnauthorizedAccessException || ex is SecurityException || ex is IOException) ? 1 : 0) != 0)
        {
            _log.Warn("proxy", "Could not restore the system proxy: " + ex.Message);
        }
    }

    public void RestoreIfStale()
    {
        using RegistryKey? registryKey = Registry.CurrentUser.OpenSubKey("Software\\NpvTunnel\\ProxyBackup");
        if (registryKey != null)
        {
            _log.Warn("proxy", "A previous session ended without cleaning up the system proxy; restoring it now.");
            Restore();
        }
    }

    private void SaveSnapshot()
    {
        using RegistryKey? registryKey = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
        ProxySnapshot proxySnapshot = new ProxySnapshot();
        if (registryKey != null)
        {
            proxySnapshot.Existed = true;
            proxySnapshot.HadProxyEnable = registryKey.GetValue("ProxyEnable") != null;
            proxySnapshot.ProxyEnable = ((registryKey.GetValue("ProxyEnable") is int num) ? num : 0);
            proxySnapshot.ProxyServer = registryKey.GetValue("ProxyServer") as string;
            proxySnapshot.ProxyOverride = registryKey.GetValue("ProxyOverride") as string;
            proxySnapshot.AutoConfigUrl = registryKey.GetValue("AutoConfigURL") as string;
            proxySnapshot.AutoConfigUrlPresent = proxySnapshot.AutoConfigUrl != null;
        }
        using RegistryKey registryKey2 = Registry.CurrentUser.CreateSubKey("Software\\NpvTunnel\\ProxyBackup", writable: true);
        registryKey2.SetValue("json", JsonSerializer.Serialize(proxySnapshot), RegistryValueKind.String);
    }

    private static ProxySnapshot? LoadSnapshot()
    {
        using RegistryKey? registryKey = Registry.CurrentUser.OpenSubKey("Software\\NpvTunnel\\ProxyBackup");
        if (!(registryKey?.GetValue("json") is string json))
        {
            return null;
        }
        try
        {
            return JsonSerializer.Deserialize<ProxySnapshot>(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    [DllImport("wininet.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetSetOption(nint hInternet, int dwOption, nint lpBuffer, int dwBufferLength);

    private static void Refresh()
    {
        InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
    }
}
