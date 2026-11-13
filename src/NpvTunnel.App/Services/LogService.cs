using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using NpvTunnel.Core.Security;

namespace NpvTunnel.App.Services;

public sealed class LogService
{
	private const int MaxEntries = 800;

	private const long MaxLogBytes = 2097152L;

	private readonly object _gate = new object();

	private readonly string _file;

	public ObservableCollection<LogEntry> Entries { get; } = new ObservableCollection<LogEntry>();


	public event EventHandler<LogEntry>? EntryAdded;

	public LogService()
	{
		AppPaths.EnsureCreated();
		_file = Path.Combine(AppPaths.LogDirectory, "npvtunnel.log");
		RotateIfNeeded();
	}

	public void Debug(string source, string message)
	{
		Add(LogLevel.Debug, source, message);
	}

	public void Info(string source, string message)
	{
		Add(LogLevel.Info, source, message);
	}

	public void Warn(string source, string message)
	{
		Add(LogLevel.Warn, source, message);
	}

	public void Error(string source, string message)
	{
		Add(LogLevel.Error, source, message);
	}

	public void Add(LogLevel level, string source, string message)
	{
		LogEntry entry = new LogEntry(DateTimeOffset.Now, level, source, Redactor.Scrub(message));
		lock (_gate)
		{
			Entries.Add(entry);
			while (Entries.Count > 800)
			{
				Entries.RemoveAt(0);
			}
			try
			{
				File.AppendAllText(_file, entry?.ToString() + Environment.NewLine, Encoding.UTF8);
			}
			catch (IOException)
			{
			}
		}
		Application current = Application.Current;
		Dispatcher val = ((current != null) ? ((DispatcherObject)current).Dispatcher : null);
		if (val == null || val.CheckAccess())
		{
			this.EntryAdded?.Invoke(this, entry);
			return;
		}
		val.BeginInvoke((Delegate)(Action)delegate
		{
			this.EntryAdded?.Invoke(this, entry);
		}, Array.Empty<object>());
	}

	public void Clear()
	{
		lock (_gate)
		{
			Entries.Clear();
		}
	}

	public string ExportRedacted()
	{
		lock (_gate)
		{
			return string.Join(Environment.NewLine, Entries.Select((LogEntry e) => e.ToString()));
		}
	}

	private void RotateIfNeeded()
	{
		try
		{
			FileInfo fileInfo = new FileInfo(_file);
			if (fileInfo.Exists && fileInfo.Length >= 2097152)
			{
				string destFileName = Path.Combine(AppPaths.LogDirectory, "npvtunnel.1.log");
				File.Move(_file, destFileName, overwrite: true);
			}
		}
		catch (IOException)
		{
		}
	}
}
