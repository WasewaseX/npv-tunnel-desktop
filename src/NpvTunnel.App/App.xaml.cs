using System.IO;
using System.Windows;
using System.Windows.Threading;
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

        // `--selftest` runs the real startup path (resources, view models, window
        // creation and the first render pass) without a user, then exits with a
        // status code. CI runs it against the published binary, which is how the
        // 1.0.0 globalization crash would have been caught before shipping.
        if (e.Args.Any(a => a.Equals("--selftest", StringComparison.OrdinalIgnoreCase)))
        {
            RunSelfTest();
            return;
        }

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
        LoadTheme(settings.Theme);
        var profiles = new ProfileRepository(Logs);
        var engine = new EngineManager(Logs);
        var proxy = new SystemProxyService(Logs);
        var association = new FileAssociationService(Logs);

        // If a previous session was killed while connected, put the machine back and
        // clear whatever it left in the runtime directory.
        proxy.RestoreIfStale();
        engine.SweepStaleRuntimeFiles(Logs);

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

    /// <summary>
    /// Swaps the palette dictionary. Only the palette differs between themes: the
    /// styles and templates live in the same file and are regenerated from one
    /// source, so a button cannot look finished in one mode and broken in the other.
    /// </summary>
    private void LoadTheme(string theme)
    {
        for (int i = Resources.MergedDictionaries.Count - 1; i >= 0; i--)
        {
            string? source = Resources.MergedDictionaries[i].Source?.OriginalString;
            if (source is not null && source.StartsWith("Themes/", StringComparison.OrdinalIgnoreCase))
            {
                Resources.MergedDictionaries.RemoveAt(i);
            }
        }

        string file = AppSettings.IsLight(theme) ? "Themes/Theme.Light.xaml" : "Themes/Theme.xaml";
        Resources.MergedDictionaries.Insert(0, new ResourceDictionary { Source = new Uri(file, UriKind.Relative) });
    }

    /// <summary>
    /// Applies a theme to a running window. WPF resolves StaticResource once, so the
    /// shell is rebuilt around the existing view model rather than left half-styled:
    /// the tunnel state, the engine process and the profile list all survive.
    /// </summary>
    public void ApplyThemeToShell(string theme)
    {
        LoadTheme(theme);

        if (MainWindow is not MainWindow old || old.DataContext is not MainViewModel viewModel)
        {
            return;
        }

        var replacement = new MainWindow
        {
            DataContext = viewModel,
            Width = old.Width,
            Height = old.Height,
            WindowState = old.WindowState,
        };

        if (!double.IsNaN(old.Left) && !double.IsNaN(old.Top))
        {
            replacement.WindowStartupLocation = WindowStartupLocation.Manual;
            replacement.Left = old.Left;
            replacement.Top = old.Top;
        }

        MainWindow = replacement;
        replacement.Show();
        old.Close();
    }

    private void RunSelfTest()
    {
        try
        {
            var settings = AppSettings.Load();
            var profiles = new ProfileRepository(Logs);
            var engine = new EngineManager(Logs);
            var proxy = new SystemProxyService(Logs);
            var association = new FileAssociationService(Logs);

            _viewModel = new MainViewModel(Logs, settings, profiles, engine, proxy, association);

            // Both palettes are rendered: a theme that only fails when selected is
            // the kind of breakage a user finds and CI should have found first.
            foreach (string theme in new[] { "dark", "light" })
            {
                LoadTheme(theme);

                var window = new MainWindow { DataContext = _viewModel };
                MainWindow = window;
                window.Show();

                // Force a layout + render pass: template/binding/resource failures
                // surface here, not in the constructor.
                Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
                window.UpdateLayout();
                Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
                window.Close();

                Logs.Info("app", $"Self-test: {theme} theme rendered.");
            }

            MainWindow = null;
            Logs.Info("app", "Self-test passed.");
            Shutdown(0);
        }
        catch (Exception ex)
        {
            Logs.Error("app", "Self-test failed: " + ex);
            Console.Error.WriteLine(ex);
            Shutdown(2);
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
