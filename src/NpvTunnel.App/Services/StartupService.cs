using System;
using System.IO;
using System.Security;
using Microsoft.Win32;

namespace NpvTunnel.App.Services;

public static class StartupService
{
	private const string RunKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

	private const string ValueName = "NpvTunnel";

	public static bool IsEnabled()
	{
		using RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
		return registryKey?.GetValue("NpvTunnel") is string;
	}

	public static void SetEnabled(bool enabled, LogService log)
	{
		try
		{
			using RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run", writable: true) ?? Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run", writable: true);
			if (enabled)
			{
				string executablePath = FileAssociationService.ExecutablePath;
				registryKey.SetValue("NpvTunnel", "\"" + executablePath + "\" --minimised", RegistryValueKind.String);
				log.Info("shell", "Enabled start with Windows.");
			}
			else
			{
				registryKey.DeleteValue("NpvTunnel", throwOnMissingValue: false);
				log.Info("shell", "Disabled start with Windows.");
			}
		}
		catch (Exception ex) when (((ex is UnauthorizedAccessException || ex is SecurityException || ex is IOException) ? 1 : 0) != 0)
		{
			log.Warn("shell", "Could not update the startup entry: " + ex.Message);
		}
	}
}
