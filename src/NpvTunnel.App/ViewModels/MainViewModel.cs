using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using Microsoft.Win32;
using NpvTunnel.App.Services;
using NpvTunnel.Core.Engine;
using NpvTunnel.Core.Import;
using NpvTunnel.Core.Models;
using NpvTunnel.Core.Security;

namespace NpvTunnel.App.ViewModels;

public sealed class MainViewModel : ViewModelBase, IDisposable
{
	private readonly LogService _log;

	private readonly AppSettings _settings;

	private readonly ProfileRepository _profiles;

	private readonly EngineManager _engine;

	private readonly SystemProxyService _proxy;

	private readonly FileAssociationService _association;

	private readonly DispatcherTimer _timer;

	private readonly DispatcherTimer _reconnectTimer;

	private ConnectionState _state;

	private string _statusDetail = "Pick a server and press connect.";

	private ProfileItemViewModel? _selectedProfile;

	private string _searchText = string.Empty;

	private string _page = "dashboard";

	private DateTimeOffset _connectedAt;

	private long _lastIn;

	private long _lastOut;

	private long _totalIn;

	private long _totalOut;

	private double _downloadRate;

	private double _uploadRate;

	private string _pingText = "—";

	private int _reconnectAttempts;

	private CancellationTokenSource? _connectCts;

	private bool _disposed;

	public ObservableCollection<ProfileItemViewModel> Profiles { get; }

	public ICollectionView ProfilesView { get; }

	public ObservableCollection<LogEntry> Logs => _log.Entries;

	public string Page
	{
		get
		{
			return _page;
		}
		set
		{
			if (Set(ref _page, value, "Page"))
			{
				OnPropertyChanged("IsDashboard");
				OnPropertyChanged("IsServers");
				OnPropertyChanged("IsLogs");
				OnPropertyChanged("IsSettings");
			}
		}
	}

	public bool IsDashboard => Page == "dashboard";

	public bool IsServers => Page == "servers";

	public bool IsLogs => Page == "logs";

	public bool IsSettings => Page == "settings";

	public ConnectionState State
	{
		get
		{
			return _state;
		}
		private set
		{
			if (Set(ref _state, value, "State"))
			{
				OnPropertyChanged("IsConnected");
				OnPropertyChanged("IsBusy");
				OnPropertyChanged("IsTransitioning");
				OnPropertyChanged("ConnectLabel");
				OnPropertyChanged("StatusBracket");
				OnPropertyChanged("StatusTitle");
				OnPropertyChanged("StatusAccent");
				ConnectCommand.RaiseCanExecuteChanged();
			}
		}
	}

	public bool IsConnected => State == ConnectionState.Connected;

	public bool IsBusy
	{
		get
		{
			ConnectionState state = State;
			if (state == ConnectionState.Connecting || state == ConnectionState.Disconnecting)
			{
				return true;
			}
			return false;
		}
	}

	public bool IsTransitioning => State == ConnectionState.Connecting;

	public string ConnectLabel => State switch
	{
		ConnectionState.Connected => "DISCONNECT", 
		ConnectionState.Connecting => "CANCEL", 
		ConnectionState.Disconnecting => "STOPPING", 
		_ => "CONNECT", 
	};

	public string StatusBracket => State switch
	{
		ConnectionState.Connected => "[ CONNECTED ]", 
		ConnectionState.Connecting => "[ CONNECTING ]", 
		ConnectionState.Disconnecting => "[ STOPPING ]", 
		ConnectionState.Faulted => "[ FAILED ]", 
		_ => "[ DISCONNECTED ]", 
	};

	public string StatusTitle => State switch
	{
		ConnectionState.Connected => "Connected", 
		ConnectionState.Connecting => "Connecting…", 
		ConnectionState.Disconnecting => "Disconnecting…", 
		ConnectionState.Faulted => "Connection failed", 
		_ => "Not connected", 
	};

	public string StatusAccent
	{
		get
		{
			switch (State)
			{
			case ConnectionState.Connected:
				return "#FF2FE3A8";
			case ConnectionState.Connecting:
			case ConnectionState.Disconnecting:
				return "#FFFFB020";
			case ConnectionState.Faulted:
				return "#FFFF5C6C";
			default:
				return "#FF7C8B9A";
			}
		}
	}

	public string StatusDetail
	{
		get
		{
			return _statusDetail;
		}
		private set
		{
			Set(ref _statusDetail, value, "StatusDetail");
		}
	}

	public ProfileItemViewModel? SelectedProfile
	{
		get
		{
			return _selectedProfile;
		}
		set
		{
			if (Set(ref _selectedProfile, value, "SelectedProfile"))
			{
				OnPropertyChanged("HasSelection");
				OnPropertyChanged("ActiveName");
				OnPropertyChanged("ActiveEndpoint");
				OnPropertyChanged("ActiveChip");
				OnPropertyChanged("ActiveSni");
				if (value != null)
				{
					_settings.ActiveProfileId = value.Id;
					_settings.Save();
				}
			}
		}
	}

	public bool HasSelection => SelectedProfile != null;

	public string ActiveName => SelectedProfile?.Name ?? "No server selected";

	public string ActiveEndpoint => SelectedProfile?.Endpoint ?? "Add or import a .npvt file";

	public string ActiveChip => SelectedProfile?.Chip ?? "—";

	public string ActiveSni
	{
		get
		{
			if (SelectedProfile != null && !string.IsNullOrEmpty(SelectedProfile.Sni))
			{
				return "SNI " + SelectedProfile.Sni;
			}
			return string.Empty;
		}
	}

	public string UptimeText
	{
		get
		{
			if (State != ConnectionState.Connected)
			{
				return "00:00:00";
			}
			TimeSpan timeSpan = DateTimeOffset.Now - _connectedAt;
			return $"{(int)timeSpan.TotalHours:00}:{timeSpan.Minutes:00}:{timeSpan.Seconds:00}";
		}
	}

	public string PingText
	{
		get
		{
			return _pingText;
		}
		private set
		{
			Set(ref _pingText, value, "PingText");
		}
	}

	public string DownloadText => FormatRate(_downloadRate);

	public string UploadText => FormatRate(_uploadRate);

	public string TotalText => FormatBytes(_totalIn) + " / " + FormatBytes(_totalOut);

	public string DownlinkTotal => FormatBytes(_totalIn);

	public string UplinkTotal => FormatBytes(_totalOut);

	public string SessionModeText
	{
		get
		{
			if (!_settings.SetSystemProxy)
			{
				return "Manual (SOCKS/HTTP)";
			}
			return "System proxy";
		}
	}

	public string ListenPorts => $"SOCKS {_settings.SocksPort} · HTTP {_settings.HttpPort}";

	public AsyncRelayCommand ConnectCommand { get; }

	public AsyncRelayCommand ImportCommand { get; }

	public AsyncRelayCommand ImportFromClipboardCommand { get; }

	public RelayCommand RemoveProfileCommand { get; }

	public RelayCommand SelectProfileCommand { get; }

	public AsyncRelayCommand PingAllCommand { get; }

	public RelayCommand ExportProfileCommand { get; }

	public AsyncRelayCommand DownloadEngineCommand { get; }

	public RelayCommand ToggleAssociationCommand { get; }

	public RelayCommand RestoreProxyCommand { get; }

	public RelayCommand ClearLogsCommand { get; }

	public RelayCommand CopyLogsCommand { get; }

	public RelayCommand OpenDataFolderCommand { get; }

	public RelayCommand NavigateCommand { get; }

	public RelayCommand FocusSearchCommand { get; }

	public bool SetSystemProxy
	{
		get
		{
			return _settings.SetSystemProxy;
		}
		set
		{
			if (_settings.SetSystemProxy != value)
			{
				_settings.SetSystemProxy = value;
				_settings.Save();
				OnPropertyChanged("SetSystemProxy");
				OnPropertyChanged("SessionModeText");
				if (IsConnected && !value)
				{
					_proxy.Restore();
				}
				else if (IsConnected)
				{
					_proxy.Apply(_settings.HttpPort);
				}
			}
		}
	}

	public bool BlockIpv6
	{
		get
		{
			return _settings.BlockIpv6;
		}
		set
		{
			SaveSetting(delegate(bool v)
			{
				_settings.BlockIpv6 = v;
			}, _settings.BlockIpv6, value, "BlockIpv6");
		}
	}

	public bool BlockQuic
	{
		get
		{
			return _settings.BlockQuic;
		}
		set
		{
			SaveSetting(delegate(bool v)
			{
				_settings.BlockQuic = v;
			}, _settings.BlockQuic, value, "BlockQuic");
		}
	}

	public bool BypassLan
	{
		get
		{
			return _settings.BypassLan;
		}
		set
		{
			SaveSetting(delegate(bool v)
			{
				_settings.BypassLan = v;
			}, _settings.BypassLan, value, "BypassLan");
		}
	}

	public bool BlockBitTorrent
	{
		get
		{
			return _settings.BlockBitTorrent;
		}
		set
		{
			SaveSetting(delegate(bool v)
			{
				_settings.BlockBitTorrent = v;
			}, _settings.BlockBitTorrent, value, "BlockBitTorrent");
		}
	}

	public bool AutoReconnect
	{
		get
		{
			return _settings.AutoReconnect;
		}
		set
		{
			SaveSetting(delegate(bool v)
			{
				_settings.AutoReconnect = v;
			}, _settings.AutoReconnect, value, "AutoReconnect");
		}
	}

	public bool AllowInsecureTls
	{
		get
		{
			return _settings.AllowInsecureTls;
		}
		set
		{
			SaveSetting(delegate(bool v)
			{
				_settings.AllowInsecureTls = v;
			}, _settings.AllowInsecureTls, value, "AllowInsecureTls");
		}
	}

	public string DnsServer
	{
		get
		{
			return _settings.DnsServer;
		}
		set
		{
			if (!(_settings.DnsServer == value))
			{
				_settings.DnsServer = value;
				_settings.Save();
				OnPropertyChanged("DnsServer");
			}
		}
	}

	public int SocksPort
	{
		get
		{
			return _settings.SocksPort;
		}
		set
		{
			if (_settings.SocksPort != value)
			{
				_settings.SocksPort = value;
				_settings.Save();
				OnPropertyChanged("SocksPort");
				OnPropertyChanged("ListenPorts");
			}
		}
	}

	public int HttpPort
	{
		get
		{
			return _settings.HttpPort;
		}
		set
		{
			if (_settings.HttpPort != value)
			{
				_settings.HttpPort = value;
				_settings.Save();
				OnPropertyChanged("HttpPort");
				OnPropertyChanged("ListenPorts");
			}
		}
	}

	public string EngineStatusText
	{
		get
		{
			if (!File.Exists(Path.Combine(AppPaths.InstallDirectory, "core", "xray.exe")))
			{
				return "Tunnel engine not installed";
			}
			return "Xray-core 26.11.9 installed";
		}
	}

	public bool EngineInstalled => File.Exists(Path.Combine(AppPaths.InstallDirectory, "core", "xray.exe"));

	public bool EngineMissing => !EngineInstalled;

	public bool StartWithWindows
	{
		get
		{
			return _settings.StartWithWindows;
		}
		set
		{
			if (_settings.StartWithWindows != value)
			{
				_settings.StartWithWindows = value;
				_settings.Save();
				StartupService.SetEnabled(value, _log);
				OnPropertyChanged("StartWithWindows");
			}
		}
	}

	public string AssociationStatus
	{
		get
		{
			if (!_association.IsRegistered())
			{
				return ".npvt is not associated with this app";
			}
			return ".npvt files open in NPV Tunnel";
		}
	}

	public bool AssociationRegistered => _association.IsRegistered();

	public string AppVersion => typeof(MainViewModel).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";

	public bool HasProfiles => Profiles.Count > 0;

	public bool HasNoProfiles => Profiles.Count == 0;

	public string ProfileCountLabel => $"({Profiles.Count})";

	public string LogCountLabel => Logs.Count == 1 ? "1 entry" : $"{Logs.Count} entries";

	public event EventHandler? SearchFocusRequested;

	public string SearchText
	{
		get
		{
			return _searchText;
		}
		set
		{
			if (Set(ref _searchText, value, "SearchText"))
			{
				ProfilesView.Refresh();
			}
		}
	}

	public MainViewModel(LogService log, AppSettings settings, ProfileRepository profiles, EngineManager engine, SystemProxyService proxy, FileAssociationService association)
	{
		//IL_01ee: Unknown result type (might be due to invalid IL or missing references)
		//IL_01f3: Unknown result type (might be due to invalid IL or missing references)
		//IL_020c: Expected O, but got Unknown
		//IL_0224: Unknown result type (might be due to invalid IL or missing references)
		//IL_0229: Unknown result type (might be due to invalid IL or missing references)
		//IL_0242: Expected O, but got Unknown
		_log = log;
		_settings = settings;
		_profiles = profiles;
		_engine = engine;
		_proxy = proxy;
		_association = association;
		Profiles = new ObservableCollection<ProfileItemViewModel>();
		ProfilesView = CollectionViewSource.GetDefaultView((object)Profiles);
		ProfilesView.Filter = FilterProfile;
		Profiles.CollectionChanged += delegate
		{
			OnPropertyChanged("ProfileCountLabel");
		};
		Logs.CollectionChanged += delegate
		{
			OnPropertyChanged("LogCountLabel");
		};
		FocusSearchCommand = new RelayCommand(delegate
		{
			SearchFocusRequested?.Invoke(this, EventArgs.Empty);
		});
		ConnectCommand = new AsyncRelayCommand(ToggleConnectionAsync, () => !IsBusy);
		ImportCommand = new AsyncRelayCommand(delegate
		{
			ImportFromDialog();
			return Task.CompletedTask;
		});
		ImportFromClipboardCommand = new AsyncRelayCommand(delegate
		{
			ImportFromClipboard();
			return Task.CompletedTask;
		});
		RemoveProfileCommand = new RelayCommand(delegate(object? p)
		{
			RemoveProfile((p as ProfileItemViewModel) ?? SelectedProfile);
		});
		SelectProfileCommand = new RelayCommand(delegate(object? p)
		{
			SelectProfile(p as ProfileItemViewModel);
		});
		PingAllCommand = new AsyncRelayCommand(PingAllAsync);
		ExportProfileCommand = new RelayCommand(delegate(object? p)
		{
			ExportProfile((p as ProfileItemViewModel) ?? SelectedProfile);
		});
		DownloadEngineCommand = new AsyncRelayCommand(DownloadEngineAsync);
		ToggleAssociationCommand = new RelayCommand(delegate
		{
			ToggleAssociation();
		});
		RestoreProxyCommand = new RelayCommand(delegate
		{
			_proxy.Restore();
		});
		ClearLogsCommand = new RelayCommand(delegate
		{
			_log.Clear();
		});
		CopyLogsCommand = new RelayCommand(delegate
		{
			CopyLogs();
		});
		OpenDataFolderCommand = new RelayCommand(delegate
		{
			OpenDataFolder();
		});
		NavigateCommand = new RelayCommand(delegate(object? p)
		{
			Page = (p as string) ?? "dashboard";
		});
		_timer = new DispatcherTimer
		{
			Interval = TimeSpan.FromSeconds(1.0)
		};
		_timer.Tick += OnTick;
		_reconnectTimer = new DispatcherTimer
		{
			Interval = TimeSpan.FromSeconds(3.0)
		};
		_reconnectTimer.Tick += OnReconnectTick;
		_engine.CoreExited += OnCoreExited;
		ReloadProfiles();
		SelectedProfile = Profiles.FirstOrDefault();
		UpdateAssociationState();
		RefreshEngineState();
	}

	private void SaveSetting(Action<bool> apply, bool current, bool value, string propertyName)
	{
		if (current != value)
		{
			apply(value);
			_settings.Save();
			OnPropertyChanged(propertyName);
		}
	}

	private async Task ToggleConnectionAsync()
	{
		if ((uint)(State - 1) <= 1u)
		{
			await DisconnectAsync().ConfigureAwait(continueOnCapturedContext: true);
		}
		else
		{
			await ConnectAsync().ConfigureAwait(continueOnCapturedContext: true);
		}
	}

	public async Task ConnectAsync()
	{
		ProfileItemViewModel item = SelectedProfile;
		if (item == null)
		{
			SetFault("Select a server first. Import a .npvt file or paste a share link.");
			return;
		}
		State = ConnectionState.Connecting;
		StatusDetail = "Connecting to " + item.Endpoint + "…";
		_reconnectAttempts = 0;
		_connectCts = new CancellationTokenSource();
		try
		{
			Profile profile = _profiles.GetProfile(item.Id) ?? throw new InvalidOperationException("The profile no longer exists.");
			profile.AllowInsecure = _settings.AllowInsecureTls || profile.AllowInsecure;
			EngineOptions options = new EngineOptions
			{
				SocksPort = _settings.SocksPort,
				HttpPort = _settings.HttpPort,
				BlockIpv6 = _settings.BlockIpv6,
				BypassLan = _settings.BypassLan,
				BlockQuic = _settings.BlockQuic,
				BlockBitTorrent = _settings.BlockBitTorrent,
				DnsServer = _settings.DnsServer,
				LogLevel = _settings.LogLevel,
				LocalOnly = true
			};
			EngineConfig engineConfig = XrayConfigBuilder.Build(profile, options);
			foreach (string warning in engineConfig.Warnings)
			{
				_log.Warn("engine", warning);
			}
			await _engine.StartAsync(_settings, engineConfig.Json, options.SocksPort, options.HttpPort, _connectCts.Token).ConfigureAwait(continueOnCapturedContext: true);
			if (_settings.SetSystemProxy)
			{
				_proxy.Apply(options.HttpPort);
			}
			_connectedAt = DateTimeOffset.Now;
			_lastIn = 0L;
			_lastOut = 0L;
			_totalIn = 0L;
			_totalOut = 0L;
			_timer.Start();
			State = ConnectionState.Connected;
			StatusDetail = (_settings.SetSystemProxy ? "Traffic is routed through the tunnel." : $"Point your apps at 127.0.0.1:{options.HttpPort} (HTTP) or {options.SocksPort} (SOCKS5).");
			_profiles.MarkConnected(item.Id);
			RefreshPingForAsync(item);
		}
		catch (OperationCanceledException)
		{
			SetFault("Connection cancelled.");
			_engine.Stop();
		}
		catch (Exception ex2)
		{
			_engine.Stop();
			_proxy.Restore();
			SetFault(ex2.Message);
			_log.Error("app", ex2.Message);
		}
		finally
		{
			_connectCts?.Dispose();
			_connectCts = null;
		}
	}

	public async Task DisconnectAsync()
	{
		State = ConnectionState.Disconnecting;
		StatusDetail = "Closing the tunnel…";
		_timer.Stop();
		_reconnectTimer.Stop();
		_connectCts?.Cancel();
		await Task.Run(delegate
		{
			_engine.Stop();
			_proxy.Restore();
		}).ConfigureAwait(continueOnCapturedContext: true);
		State = ConnectionState.Disconnected;
		StatusDetail = "Pick a server and press connect.";
		PingText = "—";
		_downloadRate = 0.0;
		_uploadRate = 0.0;
		RaiseStats();
	}

	private void SetFault(string message)
	{
		State = ConnectionState.Faulted;
		StatusDetail = Redactor.Scrub(message);
		_log.Error("app", message);
	}

	private void OnCoreExited(object? sender, int code)
	{
		Application current = Application.Current;
		if (current == null)
		{
			return;
		}
		((DispatcherObject)current).Dispatcher.BeginInvoke((Delegate)(Action)delegate
		{
			_timer.Stop();
			_proxy.Restore();
			State = ConnectionState.Faulted;
			StatusDetail = $"The tunnel core stopped unexpectedly (code {code}).";
			if (_settings.AutoReconnect && _reconnectAttempts < 3)
			{
				_reconnectAttempts++;
				StatusDetail += $" Retrying ({_reconnectAttempts}/3)…";
				_reconnectTimer.Start();
			}
		}, Array.Empty<object>());
	}

	private async void OnReconnectTick(object? sender, EventArgs e)
	{
		_reconnectTimer.Stop();
		await ConnectAsync().ConfigureAwait(continueOnCapturedContext: true);
	}

	private void OnTick(object? sender, EventArgs e)
	{
		OnPropertyChanged("UptimeText");
		if (_engine.TryGetTraffic(out var bytesIn, out var bytesOut))
		{
			long num = Math.Max(0L, bytesIn - _lastIn);
			long num2 = Math.Max(0L, bytesOut - _lastOut);
			_lastIn = bytesIn;
			_lastOut = bytesOut;
			_totalIn = bytesIn;
			_totalOut = bytesOut;
			_downloadRate = _downloadRate * 0.6 + (double)num * 0.4;
			_uploadRate = _uploadRate * 0.6 + (double)num2 * 0.4;
		}
		RaiseStats();
	}

	private void RaiseStats()
	{
		OnPropertyChanged("DownloadText");
		OnPropertyChanged("UploadText");
		OnPropertyChanged("TotalText");
		OnPropertyChanged("DownlinkTotal");
		OnPropertyChanged("UplinkTotal");
	}

	private void ReloadProfiles()
	{
		Profiles.Clear();
		foreach (StoredProfile item in _profiles.Items)
		{
			Profiles.Add(new ProfileItemViewModel(item));
		}
		OnPropertyChanged("HasProfiles");
		OnPropertyChanged("HasNoProfiles");
		Guid? activeProfileId = _settings.ActiveProfileId;
		if (activeProfileId.HasValue)
		{
			Guid activeId = activeProfileId.GetValueOrDefault();
			ProfileItemViewModel profileItemViewModel = Profiles.FirstOrDefault((ProfileItemViewModel p) => p.Id == activeId);
			if (profileItemViewModel != null)
			{
				SelectedProfile = profileItemViewModel;
			}
		}
	}

	private bool FilterProfile(object item)
	{
		if (string.IsNullOrWhiteSpace(_searchText))
		{
			return true;
		}
		if (item is ProfileItemViewModel profileItemViewModel)
		{
			if (!profileItemViewModel.Name.Contains(_searchText, StringComparison.OrdinalIgnoreCase) && !profileItemViewModel.Address.Contains(_searchText, StringComparison.OrdinalIgnoreCase))
			{
				return profileItemViewModel.Protocol.Contains(_searchText, StringComparison.OrdinalIgnoreCase);
			}
			return true;
		}
		return false;
	}

	private void SelectProfile(ProfileItemViewModel? item)
	{
		if (item != null)
		{
			SelectedProfile = item;
			Page = "dashboard";
		}
	}

	private void RemoveProfile(ProfileItemViewModel? item)
	{
		if (item != null)
		{
			if (State != 0 && SelectedProfile?.Id == item.Id)
			{
				DisconnectAsync();
			}
			_profiles.Remove(item.Id);
			Profiles.Remove(item);
			if (SelectedProfile?.Id == item.Id)
			{
				SelectedProfile = Profiles.FirstOrDefault();
			}
			OnPropertyChanged("HasProfiles");
			OnPropertyChanged("HasNoProfiles");
		}
	}

	public void ImportFromDialog()
	{
		//IL_0000: Unknown result type (might be due to invalid IL or missing references)
		//IL_0005: Unknown result type (might be due to invalid IL or missing references)
		//IL_0010: Unknown result type (might be due to invalid IL or missing references)
		//IL_001b: Unknown result type (might be due to invalid IL or missing references)
		//IL_0022: Unknown result type (might be due to invalid IL or missing references)
		//IL_002a: Expected O, but got Unknown
		OpenFileDialog val = new OpenFileDialog
		{
			Title = "Import a NPV Tunnel configuration",
			Filter = "NPV Tunnel config (*.npvt;*.npv;*.npv4;*.inpv)|*.npvt;*.npv;*.npv4;*.inpv|Share link / JSON (*.txt;*.json)|*.txt;*.json|All files (*.*)|*.*",
			CheckFileExists = true,
			Multiselect = true
		};
		if (((CommonDialog)val).ShowDialog().GetValueOrDefault())
		{
			string[] fileNames = ((FileDialog)val).FileNames;
			foreach (string path in fileNames)
			{
				ImportFromPath(path);
			}
		}
	}

	public void ImportFromClipboard()
	{
		try
		{
			if (!Clipboard.ContainsText())
			{
				SetFault("The clipboard is empty.");
			}
			else
			{
				ImportFromText(Clipboard.GetText(), "clipboard");
			}
		}
		catch (Exception ex) when (((ex is COMException || ex is OutOfMemoryException) ? 1 : 0) != 0)
		{
			SetFault("The clipboard could not be read.");
		}
	}

	public void ImportFromPath(string path)
	{
		ImportResult importResult = NpvtImporter.ImportFile(path);
		if (importResult.Error == ImportError.EncryptedNeedsPassword)
		{
			Application current = Application.Current;
			string text = Dialogs.AskPassphrase((current != null) ? current.MainWindow : null, Path.GetFileName(path));
			if (string.IsNullOrEmpty(text))
			{
				StatusDetail = "Import cancelled.";
				return;
			}
			importResult = NpvtImporter.ImportFile(path, text);
		}
		CompleteImport(importResult, Path.GetFileName(path));
	}

	public void ImportFromText(string text, string source)
	{
		ImportResult importResult = NpvtImporter.ImportText(text, null, source);
		if (importResult.Error == ImportError.EncryptedNeedsPassword)
		{
			Application current = Application.Current;
			string text2 = Dialogs.AskPassphrase((current != null) ? current.MainWindow : null, "locked configuration");
			if (string.IsNullOrEmpty(text2))
			{
				StatusDetail = "Import cancelled.";
				return;
			}
			importResult = NpvtImporter.ImportText(text, text2, source);
		}
		CompleteImport(importResult, source);
	}

	private void CompleteImport(ImportResult result, string source)
	{
		if (!result.Success || result.Profile == null)
		{
			StatusDetail = result.Message;
			_log.Warn("import", source + ": " + result.Message);
			Application current = Application.Current;
			Dialogs.Show((current != null) ? current.MainWindow : null, "Import failed", result.Message, (MessageBoxImage)48);
			return;
		}
		ProfileItemViewModel profileItemViewModel = new ProfileItemViewModel(_profiles.Add(result.Profile));
		Profiles.Add(profileItemViewModel);
		SelectedProfile = profileItemViewModel;
		OnPropertyChanged("HasProfiles");
		OnPropertyChanged("HasNoProfiles");
		foreach (string warning in result.Warnings)
		{
			_log.Warn("import", warning);
		}
		StatusDetail = "Imported “" + profileItemViewModel.Name + "”.";
		Page = "dashboard";
		RefreshPingForAsync(profileItemViewModel);
	}

	private void ExportProfile(ProfileItemViewModel? item)
	{
		//IL_0025: Unknown result type (might be due to invalid IL or missing references)
		//IL_002a: Unknown result type (might be due to invalid IL or missing references)
		//IL_0035: Unknown result type (might be due to invalid IL or missing references)
		//IL_0040: Unknown result type (might be due to invalid IL or missing references)
		//IL_005c: Expected O, but got Unknown
		if (item == null)
		{
			SetFault("Select a profile to export.");
			return;
		}
		Profile profile = _profiles.GetProfile(item.Id);
		if (profile == null)
		{
			return;
		}
		SaveFileDialog val = new SaveFileDialog
		{
			Title = "Export profile",
			Filter = "NPV Tunnel config (*.npvt)|*.npvt|JSON (*.json)|*.json",
			FileName = SanitiseFileName(item.Name) + ".npvt"
		};
		if (!((CommonDialog)val).ShowDialog().GetValueOrDefault())
		{
			return;
		}
		string text = NpvtDocument.FromProfile(profile).ToJson();
		Application current = Application.Current;
		string text2 = Dialogs.AskPassphrase((current != null) ? current.MainWindow : null, "Optional: type a passphrase to lock the exported file (leave empty for plain npvt/1).", allowEmpty: true);
		try
		{
			if (!string.IsNullOrEmpty(text2))
			{
				text = LockedConfig.Lock(text, text2);
			}
			File.WriteAllText(((FileDialog)val).FileName, text);
			StatusDetail = "Profile exported.";
			_log.Info("export", "Exported profile to " + Path.GetFileName(((FileDialog)val).FileName) + ".");
		}
		catch (Exception ex) when (((ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException) ? 1 : 0) != 0)
		{
			SetFault("The profile could not be exported: " + ex.Message);
		}
	}

	private static string SanitiseFileName(string name)
	{
		char[] invalidFileNameChars = Path.GetInvalidFileNameChars();
		foreach (char oldChar in invalidFileNameChars)
		{
			name = name.Replace(oldChar, '_');
		}
		if (!string.IsNullOrWhiteSpace(name))
		{
			return name.Trim();
		}
		return "profile";
	}

	private async Task PingAllAsync()
	{
		SemaphoreSlim gate = new SemaphoreSlim(4);
		try
		{
			await Task.WhenAll(((IEnumerable<ProfileItemViewModel>)Profiles).Select((Func<ProfileItemViewModel, Task>)async delegate(ProfileItemViewModel item)
			{
				await gate.WaitAsync().ConfigureAwait(continueOnCapturedContext: true);
				try
				{
					await RefreshPingForAsync(item).ConfigureAwait(continueOnCapturedContext: true);
				}
				finally
				{
					gate.Release();
				}
			})).ConfigureAwait(continueOnCapturedContext: true);
		}
		finally
		{
			if (gate != null)
			{
				((IDisposable)gate).Dispose();
			}
		}
	}

	private async Task RefreshPingForAsync(ProfileItemViewModel item)
	{
		long num = await PingService.MeasureAsync(item.Address, item.Port, TimeSpan.FromSeconds(3.0), CancellationToken.None).ConfigureAwait(continueOnCapturedContext: true);
		item.SetPing(num);
		_profiles.UpdatePing(item.Id, num);
		if (SelectedProfile?.Id == item.Id)
		{
			PingText = ((num <= 0) ? "—" : $"{num} ms");
		}
	}

	private async Task DownloadEngineAsync()
	{
		if (EngineInstalled)
		{
			StatusDetail = "The engine is already installed.";
			return;
		}
		try
		{
			State = ConnectionState.Connecting;
			StatusDetail = "Downloading the tunnel engine…";
			await EngineInstaller.DownloadAndInstallAsync(new Progress<double>(delegate(double p)
			{
				StatusDetail = $"Downloading the tunnel engine… {p:P0}";
			}), _log, CancellationToken.None).ConfigureAwait(continueOnCapturedContext: true);
			StatusDetail = "Tunnel engine installed.";
			RefreshEngineState();
		}
		catch (Exception ex)
		{
			SetFault(ex.Message);
		}
		finally
		{
			if (State == ConnectionState.Connecting)
			{
				State = ConnectionState.Disconnected;
			}
		}
	}

	private void ToggleAssociation()
	{
		if (_association.IsRegistered())
		{
			_association.Unregister();
			StatusDetail = "Removed the .npvt file association.";
		}
		else
		{
			_association.Register();
			StatusDetail = ".npvt files now open in NPV Tunnel.";
		}
		UpdateAssociationState();
	}

	private void UpdateAssociationState()
	{
		OnPropertyChanged("AssociationStatus");
		OnPropertyChanged("AssociationRegistered");
	}

	private void RefreshEngineState()
	{
		OnPropertyChanged("EngineInstalled");
		OnPropertyChanged("EngineMissing");
		OnPropertyChanged("EngineStatusText");
		DownloadEngineCommand.RaiseCanExecuteChanged();
	}

	private void CopyLogs()
	{
		try
		{
			Clipboard.SetText(_log.ExportRedacted());
			StatusDetail = "Redacted log copied to the clipboard.";
		}
		catch (Exception ex) when (((ex is COMException || ex is OutOfMemoryException) ? 1 : 0) != 0)
		{
		}
	}

	private void OpenDataFolder()
	{
		try
		{
			Process.Start(new ProcessStartInfo
			{
				FileName = AppPaths.Root,
				UseShellExecute = true
			});
		}
		catch (Exception ex) when (((ex is Win32Exception || ex is IOException) ? 1 : 0) != 0)
		{
			SetFault("The data folder could not be opened.");
		}
	}

	private static string FormatRate(double bytesPerSecond)
	{
		if (!(bytesPerSecond < 1.0))
		{
			if (!(bytesPerSecond < 1024.0))
			{
				if (!(bytesPerSecond < 1048576.0))
				{
					return $"{bytesPerSecond / 1048576.0:0.0} MB/s";
				}
				return $"{bytesPerSecond / 1024.0:0.0} KB/s";
			}
			return $"{bytesPerSecond:0} B/s";
		}
		return "0 B/s";
	}

	private static string FormatBytes(long bytes)
	{
		if (bytes < 1048576)
		{
			if (bytes >= 1024)
			{
				return $"{(double)bytes / 1024.0:0.0} KB";
			}
			return $"{bytes} B";
		}
		if (bytes >= 1073741824)
		{
			return $"{(double)bytes / 1073741824.0:0.00} GB";
		}
		return $"{(double)bytes / 1048576.0:0.0} MB";
	}

	public void HandleFileOpen(string path)
	{
		string path2 = path;
		Application current = Application.Current;
		if (current == null)
		{
			return;
		}
		((DispatcherObject)current).Dispatcher.Invoke((Action)delegate
		{
			if (!File.Exists(path2))
			{
				StatusDetail = "The file no longer exists.";
			}
			else if (!NpvtImporter.IsSupportedExtension(path2))
			{
				StatusDetail = "That file type is not a NPV Tunnel configuration.";
			}
			else
			{
				ImportFromPath(path2);
				ActivateWindow();
			}
		});
	}

	public static void ActivateWindow()
	{
		//IL_0017: Unknown result type (might be due to invalid IL or missing references)
		//IL_001d: Invalid comparison between Unknown and I4
		Application current = Application.Current;
		Window val = ((current != null) ? current.MainWindow : null);
		if (val != null)
		{
			if ((int)val.WindowState == 1)
			{
				val.WindowState = (WindowState)0;
			}
			val.Activate();
			val.Topmost = true;
			val.Topmost = false;
		}
	}

	public void Dispose()
	{
		if (!_disposed)
		{
			_disposed = true;
			_timer.Stop();
			_reconnectTimer.Stop();
			_engine.CoreExited -= OnCoreExited;
			_connectCts?.Cancel();
			_connectCts?.Dispose();
			_engine.Dispose();
		}
	}
}
