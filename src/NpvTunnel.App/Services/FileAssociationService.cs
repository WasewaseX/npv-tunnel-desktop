using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32;

namespace NpvTunnel.App.Services;

public sealed class FileAssociationService
{
    public const string Extension = ".npvt";

    public const string ProgId = "NpvTunnel.Config";

    private readonly LogService _log;

    public static string ExecutablePath => Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? "NpvTunnel.exe";

    public FileAssociationService(LogService log)
    {
        _log = log;
    }

    public bool IsRegistered()
    {
        using RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\\Classes\\.npvt");
        string a = registryKey?.GetValue(null) as string;
        using RegistryKey registryKey2 = Registry.CurrentUser.OpenSubKey("Software\\Classes\\NpvTunnel.Config\\shell\\open\\command");
        string text = registryKey2?.GetValue(null) as string;
        return string.Equals(a, "NpvTunnel.Config", StringComparison.OrdinalIgnoreCase) && text != null && text.Contains(ExecutablePath, StringComparison.OrdinalIgnoreCase);
    }

    public bool Register()
    {
        try
        {
            string executablePath = ExecutablePath;
            using (RegistryKey registryKey = Registry.CurrentUser.CreateSubKey("Software\\Classes\\.npvt"))
            {
                registryKey.SetValue(null, "NpvTunnel.Config", RegistryValueKind.String);
                registryKey.SetValue("Content Type", "application/x-npvt", RegistryValueKind.String);
                registryKey.SetValue("PerceivedType", "text", RegistryValueKind.String);
                using RegistryKey registryKey2 = registryKey.CreateSubKey("OpenWithProgids");
                registryKey2.SetValue("NpvTunnel.Config", Array.Empty<byte>(), RegistryValueKind.None);
            }
            using (RegistryKey registryKey3 = Registry.CurrentUser.CreateSubKey("Software\\Classes\\NpvTunnel.Config"))
            {
                registryKey3.SetValue(null, "NPV Tunnel configuration", RegistryValueKind.String);
                using RegistryKey registryKey4 = registryKey3.CreateSubKey("DefaultIcon");
                registryKey4.SetValue(null, "\"" + executablePath + "\",0", RegistryValueKind.String);
                using RegistryKey registryKey5 = registryKey3.CreateSubKey("shell\\open\\command");
                registryKey5.SetValue(null, "\"" + executablePath + "\" \"%1\"", RegistryValueKind.String);
                using RegistryKey registryKey6 = registryKey3.CreateSubKey("shell");
                registryKey6.SetValue(null, "open", RegistryValueKind.String);
            }
            NotifyShell();
            _log.Info("shell", "Registered .npvt → NpvTunnel.Config for the current user.");
            return true;
        }
        catch (Exception ex) when (((ex is UnauthorizedAccessException || ex is SecurityException || ex is IOException) ? 1 : 0) != 0)
        {
            _log.Error("shell", "Could not register the .npvt handler: " + ex.Message);
            return false;
        }
    }

    public bool Unregister()
    {
        try
        {
            Registry.CurrentUser.DeleteSubKeyTree("Software\\Classes\\NpvTunnel.Config", throwOnMissingSubKey: false);
            using (RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\\Classes\\.npvt", writable: true))
            {
                if (registryKey != null)
                {
                    if (string.Equals(registryKey.GetValue(null) as string, "NpvTunnel.Config", StringComparison.OrdinalIgnoreCase))
                    {
                        registryKey.DeleteValue(string.Empty, throwOnMissingValue: false);
                    }
                    using RegistryKey registryKey2 = registryKey.OpenSubKey("OpenWithProgids", writable: true);
                    registryKey2?.DeleteValue("NpvTunnel.Config", throwOnMissingValue: false);
                }
            }
            NotifyShell();
            _log.Info("shell", "Removed the .npvt handler.");
            return true;
        }
        catch (Exception ex) when (((ex is UnauthorizedAccessException || ex is SecurityException || ex is IOException) ? 1 : 0) != 0)
        {
            _log.Error("shell", "Could not remove the .npvt handler: " + ex.Message);
            return false;
        }
    }

    [DllImport("shell32.dll")]
    private static extern void SHChangeNotify(int eventId, uint flags, nint item1, nint item2);

    private static void NotifyShell()
    {
        SHChangeNotify(134217728, 0u, IntPtr.Zero, IntPtr.Zero);
    }
}
