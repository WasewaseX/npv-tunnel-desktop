using System;
using System.IO;

namespace NpvTunnel.App.Services;

public static class AppPaths
{
	public static string Root { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NpvTunnel");


	public static string ProfilesFile => Path.Combine(Root, "profiles.dat");

	public static string SettingsFile => Path.Combine(Root, "settings.json");

	public static string LogDirectory => Path.Combine(Root, "logs");

	public static string RuntimeDirectory => Path.Combine(Root, "runtime");

	public static string InstallDirectory => AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);

	public static string? ExecutablePath => Environment.ProcessPath;

	public static void EnsureCreated()
	{
		Directory.CreateDirectory(Root);
		Directory.CreateDirectory(LogDirectory);
		Directory.CreateDirectory(RuntimeDirectory);
	}
}
