using System.IO;
using System.Windows;
using NpvTunnel.App.Services;
using NpvTunnel.App.ViewModels;

namespace NpvTunnel.App;

public partial class App : Application
{
    private SingleInstance? _instance;
    private MainViewModel? _viewModel;

    public static LogService Logs { get; private set; } = null!;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        AppPaths.EnsureCreated();
        Logs = new LogService();
        Logs.Info("app", $"NPV Tunnel Desktop {typeof(App).Assembly.GetName().Version} starting.");

        HookCrashHandlers();

        _instance = new SingleInstance();
        if (!_instance.TryAcquire())
        {
            // Another instance owns the tunnel: hand over the file and exit quietly.
            var file = FirstConfigArgument(e.Args);
            if (file is not null)
            {
                _instance.TrySendToPrimary(file, TimeSpan.FromSeconds(3));
            }
            else
            {
                MainViewModel.ActivateWindow();
            }

            Shutdown();
            return;
        }

        var settings = AppSettings.Load();
        var profiles = new ProfileRepository(Logs);
        var engine = new EngineManager(Logs);
        var proxy = new SystemProxyService(Logs);
        var association = new FileAssociationService(Logs);

        // If a previous session was killed while connected, put the machine back.
        proxy.RestoreIfStale();

        _viewModel = new MainViewModel(Logs, settings, profiles, engine, proxy, association);

        var window = new MainWindow { DataContext = _viewModel };
        MainWindow = window;
        window.Show();

        // "Start with Windows" launches us minimised.
        if (e.Args.Any(a => a.Equals("--minimised", StringComparison.OrdinalIgnoreCase)))
        {
            window.WindowState = WindowState.Minimized;
        }

        _instance.FileReceived += path => Dispatcher.BeginInvoke(() => _viewModel.HandleFileOpen(path));
        _instance.StartServer();

        var startupFile = FirstConfigArgument(e.Args);
        if (startupFile is not null)
        {
            _viewModel.HandleFileOpen(startupFile);
        }
        else if (!settings.FileAssociationOffered)
        {
            settings.FileAssociationOffered = true;
            settings.Save();
            OfferAssociation(association);
        }
    }

    private void OfferAssociation(FileAssociationService association)
    {
        if (association.IsRegistered())
        {
            return;
        }

        var answer = MessageBox.Show(
            "Make NPV Tunnel the default app for .npvt configuration files?\n\n" +
            "This registers the handler for your Windows account only — no administrator rights, " +
            "and you can undo it any time in Settings.",
            "NPV Tunnel",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question,
            MessageBoxResult.Yes);

        if (answer == MessageBoxResult.Yes)
        {
            association.Register();
        }
    }

    private static string? FirstConfigArgument(IReadOnlyList<string> args)
    {
        foreach (var arg in args)
        {
            if (string.IsNullOrWhiteSpace(arg) || arg.StartsWith('-'))
            {
                continue;
            }

            if (File.Exists(arg) && NpvTunnel.Core.Import.NpvtImporter.IsSupportedExtension(arg))
            {
                return arg;
            }
        }

        return null;
    }

    private void HookCrashHandlers()
    {
        DispatcherUnhandledException += (_, args) =>
        {
            Logs.Error("crash", args.Exception.ToString());
            MessageBox.Show(
                "NPV Tunnel hit an unexpected error.\n\n" +
                NpvTunnel.Core.Security.Redactor.Scrub(args.Exception.Message) +
                "\n\nThe tunnel has been closed. Details are in the log view.",
                "NPV Tunnel",
                MessageBoxButton.OK,
                MessageBoxImage.Error);

            try
            {
                _viewModel?.Dispose();
            }
            catch (Exception)
            {
            }

            args.Handled = true;
            Shutdown(1);
        };

        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception ex)
            {
                Logs.Error("crash", "Unhandled: " + ex);
            }
        };

        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            Logs.Error("crash", "Unobserved task exception: " + args.Exception);
            args.SetObserved();
        };
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            _viewModel?.Dispose();
        }
        catch (Exception)
        {
        }

        _instance?.Dispose();
        Logs.Info("app", "NPV Tunnel Desktop exited.");
        base.OnExit(e);
    }
}
