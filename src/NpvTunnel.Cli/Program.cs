using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using NpvTunnel.Core.Engine;
using NpvTunnel.Core.Import;
using NpvTunnel.Core.Models;
using NpvTunnel.Core.Security;

namespace NpvTunnel.Cli;

/// <summary>
/// The Linux build of NPV Tunnel: same importer and same engine builder as the
/// Windows shell, without the WPF front end. Config files from channels import,
/// check and run here.
/// </summary>
public static class Program
{
    private const string Usage = """
        npvtunnel - NPV Tunnel for Linux

        npvtunnel import <file.npvt|link|json> [--name <label>]
            Import every configuration in a source into the local store.

        npvtunnel list
            Show what is stored, with the audit result for each entry.

        npvtunnel show <index|id>
            Print one configuration (credentials are redacted unless --reveal).

        npvtunnel remove <index|id>
            Delete an entry.

        npvtunnel config <index|id> [-o file.json] [--socks N] [--http N]
            Write the Xray config this app would run.

        npvtunnel check <index|id>
            Audit one entry and test its generated config with the engine.

        npvtunnel connect <index|id> [--socks N] [--http N]
            Run the tunnel in the foreground until Ctrl+C.

        npvtunnel where
            Print the paths this build uses: store, key, engine.

        npvtunnel selftest [--emit <file>]
            Exercise the parser, the audit and the engine on this machine.
            --emit also writes the synthetic container it uses, for packaging tests.

        --store <path>   use a different profile store
        --engine <path>  use a specific xray binary instead of the bundled one
        --trust-engine   required together with --engine: you vouch for that binary
        """;

    public static int Main(string[] args)
    {
        try
        {
            return Run(args);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine("error: " + ex.Message);
            return 1;
        }
    }

    private static int Run(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            Console.WriteLine(Usage);
            return 0;
        }

        Options options = Options.Parse(args);
        var positional = options.Positional;

        string command = positional.FirstOrDefault() ?? string.Empty;
        var store = new ProfileStore(options.Get("--store"));
        List<Profile> profiles = store.Load();

        switch (command)
        {
            case "import":
                return Import(positional, options, store, profiles);

            case "list":
                return List_(profiles);

            case "show":
                return Show(positional, profiles, options.HasFlag("--reveal"));

            case "remove":
                return Remove(positional, store, profiles);

            case "config":
                return WriteConfig(positional, options, profiles);

            case "check":
                return Check(positional, options, profiles);

            case "connect":
                return Connect(positional, options, profiles);

            case "where":
                var whereStore = new ProfileStore(options.Get("--store"));
                Console.WriteLine("store    " + whereStore.FilePath + (File.Exists(whereStore.FilePath) ? string.Empty : " (not created yet)"));
                Console.WriteLine("key      " + whereStore.KeyPath + (File.Exists(whereStore.KeyPath) ? string.Empty : " (not created yet)"));
                Console.WriteLine("engine   " + (options.Get("--engine") ?? EngineLocator.Find() ?? "not found"));
                return 0;

            case "selftest":
                string? emit = options.Get("--emit");
                if (!string.IsNullOrEmpty(emit))
                {
                    string? emitDirectory = Path.GetDirectoryName(Path.GetFullPath(emit));
                    if (!string.IsNullOrEmpty(emitDirectory))
                    {
                        Directory.CreateDirectory(emitDirectory);
                    }

                    File.WriteAllText(emit, SelfTest.BuildContainer());
                    Console.WriteLine("wrote synthetic container to " + emit);
                }

                return SelfTest.Run(options.Get("--engine"), options.HasFlag("--trust-engine"));

            default:
                Console.Error.WriteLine($"Unknown command '{command}'.");
                Console.WriteLine(Usage);
                return 2;
        }
    }

    private static int Import(List<string> positional, Options options, ProfileStore store, List<Profile> profiles)
    {
        if (positional.Count < 2)
        {
            Console.Error.WriteLine("import needs a file or a share link.");
            return 2;
        }

        string source = positional[1];
        string text = File.Exists(source) ? File.ReadAllText(source) : source;
        string label = File.Exists(source) ? Path.GetFileName(source) : "clipboard";

        ImportBatch batch = NpvtImporter.ImportAll(text, null, label);
        if (!batch.Success)
        {
            Console.Error.WriteLine("import failed: " + batch.Message);
            return 1;
        }

        string? nameOverride = options.Get("--name");
        int added = 0;
        foreach (Profile profile in batch.Profiles)
        {
            if (!string.IsNullOrWhiteSpace(nameOverride))
            {
                profile.Name = batch.ImportedCount == 1 ? nameOverride : $"{nameOverride} {++added}";
            }
            else
            {
                added++;
            }

            profiles.Add(profile);
        }

        store.Save(profiles);

        Console.WriteLine($"imported {batch.ImportedCount} configuration(s) from {label}");
        if (batch.FailedCount > 0)
        {
            Console.WriteLine($"skipped {batch.FailedCount} entr{(batch.FailedCount == 1 ? "y" : "ies")}");
        }

        foreach (string warning in batch.Warnings)
        {
            Console.WriteLine("  note: " + warning);
        }

        return 0;
    }

    private static int List_(List<Profile> profiles)
    {
        if (profiles.Count == 0)
        {
            Console.WriteLine("No configurations stored. Run: npvtunnel import <file>");
            return 0;
        }

        for (int i = 0; i < profiles.Count; i++)
        {
            Profile profile = profiles[i];
            IReadOnlyList<ConfigAudit.Finding> findings = ConfigAudit.Review(profile);
            string mark = ConfigAudit.BlocksConnect(findings) ? "x" : findings.Any(f => f.Severity == ConfigAudit.Severity.Warning) ? "!" : "+";
            Console.WriteLine($"{mark} [{i}] {profile.Name}");
            Console.WriteLine($"      {profile.Protocol.ToString().ToLowerInvariant()} {profile.Address}:{profile.Port} {DescribeTransport(profile)}");
        }

        Console.WriteLine();
        Console.WriteLine("+ clean   ! warnings   x refused (see: npvtunnel check <index>)");
        return 0;
    }

    private static int Show(List<string> positional, List<Profile> profiles, bool reveal)
    {
        if (!TryResolve(positional, profiles, out Profile? profile, out int index))
        {
            return 1;
        }

        Console.WriteLine($"index       {index}");
        Console.WriteLine($"id          {profile!.Id}");
        Console.WriteLine($"name        {profile.Name}");
        Console.WriteLine($"protocol    {profile.Protocol.ToString().ToLowerInvariant()}");
        Console.WriteLine($"server      {profile.Address}:{profile.Port}");
        Console.WriteLine($"transport   {DescribeTransport(profile)}");
        Console.WriteLine($"security    {profile.Security.ToString().ToLowerInvariant()}");
        Console.WriteLine($"sni         {Display(profile.Sni)}");
        Console.WriteLine($"flow        {Display(profile.Flow)}");
        Console.WriteLine($"uuid        {Secret(profile.Uuid, reveal)}");
        Console.WriteLine($"password    {Secret(profile.Password, reveal)}");

        EndpointResolver.Resolution resolution = EndpointResolver.Resolve(profile.Address);
        Console.WriteLine($"resolves    {DescribeResolution(resolution)}");

        foreach (ConfigAudit.Finding finding in ConfigAudit.Review(profile, resolution))
        {
            Console.WriteLine($"audit       {finding.Severity.ToString().ToLowerInvariant()}: {finding.Message}");
        }

        return 0;
    }

    private static int Remove(List<string> positional, ProfileStore store, List<Profile> profiles)
    {
        if (!TryResolve(positional, profiles, out Profile? profile, out _))
        {
            return 1;
        }

        profiles.Remove(profile!);
        store.Save(profiles);
        Console.WriteLine("removed.");
        return 0;
    }

    private static int WriteConfig(List<string> positional, Options options, List<Profile> profiles)
    {
        if (!TryResolve(positional, profiles, out Profile? profile, out _))
        {
            return 1;
        }

        (IReadOnlyList<ConfigAudit.Finding> findings, EngineOptions engineOptions) = AuditForConnect(profile!, options);
        if (ConfigAudit.BlocksConnect(findings))
        {
            Console.Error.WriteLine("refused: this configuration failed the safety audit.");
            foreach (ConfigAudit.Finding finding in findings.Where(f => f.Severity == ConfigAudit.Severity.Refused))
            {
                Console.Error.WriteLine("  " + finding.Message);
            }

            return 1;
        }

        EngineConfig config = XrayConfigBuilder.Build(profile!, engineOptions);

        string? output = options.Get("-o") ?? options.Get("--out");
        if (output is null)
        {
            Console.WriteLine(config.Json);
            return 0;
        }

        File.WriteAllText(output, config.Json);
        Console.WriteLine("written: " + output);
        return 0;
    }

    private static int Check(List<string> positional, Options options, List<Profile> profiles)
    {
        if (!TryResolve(positional, profiles, out Profile? profile, out _))
        {
            return 1;
        }

        EndpointResolver.Resolution resolution = EndpointResolver.Resolve(profile!.Address);
        IReadOnlyList<ConfigAudit.Finding> findings = ConfigAudit.Review(profile, resolution);
        Console.WriteLine($"audit for '{profile.Name}'");
        Console.WriteLine($"  endpoint {DescribeResolution(resolution)}");
        if (findings.Count == 0)
        {
            Console.WriteLine("  no findings");
        }

        foreach (ConfigAudit.Finding finding in findings)
        {
            Console.WriteLine($"  {finding.Severity.ToString().ToLowerInvariant(),-8} {finding.Message}");
        }

        if (ConfigAudit.BlocksConnect(findings))
        {
            // Nothing to hand the engine: the audit already blocks connect.
            Console.WriteLine("engine    not started (configuration refused above)");
            return 1;
        }

        EngineRunner? runner = OpenEngine(options, out string? engineError);
        if (runner is null)
        {
            Console.WriteLine("engine    " + engineError);
            // Asking for a specific binary and being refused is a failure; having no
            // engine installed at all still lets the audit be useful on its own.
            return options.Get("--engine") is null ? 0 : 1;
        }

        using var checkRunner = runner;
        if (!checkRunner.VerifyDigest(out string digestMessage, trustCustomEngine: checkRunner.IsCustom))
        {
            Console.WriteLine("engine    " + digestMessage);
            return 1;
        }

        Console.WriteLine("engine    " + digestMessage);

        EngineOptions engineOptions = ReadEngineOptions(options);
        IPAddress? pin = EndpointResolver.PinCandidate(resolution, engineOptions.BlockIpv6);
        if (pin is not null && !resolution.IsLiteral)
        {
            engineOptions.PinnedEndpointAddress = pin.ToString();
            Console.WriteLine($"  pinned   {pin} (the engine dials this address, not the name again)");
        }

        string configPath = checkRunner.WriteConfig(profile, engineOptions);
        bool ok = checkRunner.TestConfig(configPath, out string output);
        Console.WriteLine(ok ? "engine    config accepted by xray -test" : "engine    xray rejected the config:");
        if (!ok)
        {
            Console.WriteLine(output);
        }

        return ok && !ConfigAudit.BlocksConnect(findings) ? 0 : 1;
    }

    private static int Connect(List<string> positional, Options options, List<Profile> profiles)
    {
        if (!TryResolve(positional, profiles, out Profile? profile, out _))
        {
            return 1;
        }

        (IReadOnlyList<ConfigAudit.Finding> findings, EngineOptions engineOptions) = AuditForConnect(profile!, options);
        if (ConfigAudit.BlocksConnect(findings))
        {
            Console.Error.WriteLine("refused: this configuration failed the safety audit.");
            foreach (ConfigAudit.Finding finding in findings.Where(f => f.Severity == ConfigAudit.Severity.Refused))
            {
                Console.Error.WriteLine("  " + finding.Message);
            }

            return 1;
        }

        EngineRunner? opened = OpenEngine(options, out string? engineError);
        if (opened is null)
        {
            Console.Error.WriteLine(engineError);
            return 1;
        }

        using var runner = opened;
        if (!runner.VerifyDigest(out string digestMessage, trustCustomEngine: runner.IsCustom))
        {
            Console.Error.WriteLine(digestMessage);
            return 1;
        }

        Console.WriteLine(digestMessage);
        if (!string.IsNullOrEmpty(engineOptions.PinnedEndpointAddress))
        {
            Console.WriteLine($"endpoint  {profile!.Address} pinned to {engineOptions.PinnedEndpointAddress}");
        }

        string configPath = runner.WriteConfig(profile!, engineOptions);
        if (!runner.TestConfig(configPath, out string testOutput))
        {
            Console.Error.WriteLine("The engine rejected the generated config:");
            Console.Error.WriteLine(testOutput);
            return 1;
        }

        if (!runner.Start(configPath, out string startMessage))
        {
            Console.Error.WriteLine(startMessage);
            return 1;
        }

        Console.WriteLine($"connected to {profile!.Name}");
        Console.WriteLine($"  socks5 127.0.0.1:{engineOptions.SocksPort}");
        Console.WriteLine($"  http   127.0.0.1:{engineOptions.HttpPort}");
        Console.WriteLine($"  export  ALL_PROXY=socks5h://127.0.0.1:{engineOptions.SocksPort}");
        Console.WriteLine("Ctrl+C to stop.");

        var stop = new ManualResetEventSlim();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            stop.Set();
        };

        stop.Wait();
        runner.Stop();
        Console.WriteLine("disconnected.");
        return 0;
    }

    /// <summary>
    /// Resolves the endpoint once, reviews the profile with that answer, and returns
    /// the engine options with the audited address pinned. A hostname that resolves
    /// into private space is refused here - the same check the Windows app makes
    /// before it starts the core.
    /// </summary>
    /// <summary>
    /// Opens the engine this command may start. The bundled binary is checked against
    /// the digest compiled into this build; a binary the user pointed at needs the
    /// explicit --trust-engine opt-in, because nothing here knows what it should be.
    /// </summary>
    private static EngineRunner? OpenEngine(Options options, out string? error)
    {
        error = null;
        string? explicitPath = options.Get("--engine");
        bool trusted = options.HasFlag("--trust-engine");
        string? path = explicitPath ?? EngineLocator.Find();
        if (path is null)
        {
            error = "The tunnel engine was not found. Install the release archive, or pass --engine <path> --trust-engine.";
            return null;
        }

        if (explicitPath is not null && !trusted)
        {
            error = "Refusing to run a binary you pointed at: digest pins in this build cover the bundled engine only. Pass --trust-engine if you have checked that file yourself.";
            return null;
        }

        return new EngineRunner(path) { IsCustom = explicitPath is not null };
    }

    private static (IReadOnlyList<ConfigAudit.Finding> Findings, EngineOptions Options) AuditForConnect(Profile profile, Options options)
    {
        EndpointResolver.Resolution resolution = EndpointResolver.Resolve(profile.Address);
        IReadOnlyList<ConfigAudit.Finding> findings = ConfigAudit.Review(profile, resolution);

        EngineOptions engineOptions = ReadEngineOptions(options);
        IPAddress? pin = EndpointResolver.PinCandidate(resolution, engineOptions.BlockIpv6);
        if (pin is not null && !resolution.IsLiteral)
        {
            engineOptions.PinnedEndpointAddress = pin.ToString();
        }

        return (findings, engineOptions);
    }

    private static string DescribeResolution(EndpointResolver.Resolution resolution)
    {
        if (resolution.IsLiteral)
        {
            return resolution.Host + " (literal address)";
        }

        if (!resolution.Resolved)
        {
            return resolution.Host + " (not resolved: " + resolution.Failure + ")";
        }

        var parts = new List<string>();
        if (resolution.PublicAddresses.Count > 0)
        {
            parts.Add(string.Join(", ", resolution.PublicAddresses));
        }

        if (resolution.HasPrivate)
        {
            parts.Add("private " + string.Join(", ", resolution.PrivateAddresses));
        }

        return resolution.Host + " -> " + string.Join("; ", parts);
    }

    private static EngineOptions ReadEngineOptions(Options options)
    {
        var engineOptions = new EngineOptions
        {
            // Public configs get the strict profile by default.
            BlockIpv6 = true,
            BlockQuic = true,
            BypassLan = true,
            LocalOnly = true,
        };

        if (int.TryParse(options.Get("--socks"), NumberStyles.Integer, CultureInfo.InvariantCulture, out int socks))
        {
            engineOptions.SocksPort = socks;
        }

        if (int.TryParse(options.Get("--http"), NumberStyles.Integer, CultureInfo.InvariantCulture, out int http))
        {
            engineOptions.HttpPort = http;
        }

        return engineOptions;
    }

    private static bool TryResolve(List<string> positional, List<Profile> profiles, out Profile? profile, out int index)
    {
        profile = null;
        index = -1;

        if (positional.Count < 2)
        {
            Console.Error.WriteLine("Which configuration? Pass an index (see: npvtunnel list) or an id.");
            return false;
        }

        if (profiles.Count == 0)
        {
            Console.Error.WriteLine("Nothing is stored yet. Run: npvtunnel import <file>");
            return false;
        }

        string key = positional[1];
        if (int.TryParse(key, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed)
            && parsed >= 0 && parsed < profiles.Count)
        {
            index = parsed;
            profile = profiles[parsed];
            return true;
        }

        profile = profiles.FirstOrDefault(p => p.Id.ToString().StartsWith(key, StringComparison.OrdinalIgnoreCase));
        if (profile is null)
        {
            Console.Error.WriteLine($"No configuration matches '{key}'.");
            return false;
        }

        index = profiles.IndexOf(profile);
        return true;
    }

    private static string DescribeTransport(Profile profile)
    {
        string transport = profile.Transport switch
        {
            Transport.WebSocket => "ws",
            Transport.Grpc => "grpc",
            Transport.HttpUpgrade => "httpupgrade",
            Transport.Xhttp => "xhttp",
            Transport.Quic => "quic",
            _ => "tcp",
        };

        string security = profile.Security switch
        {
            SecurityLayer.Tls => "tls",
            SecurityLayer.Reality => "reality",
            _ => "none",
        };

        return $"{transport}/{security}";
    }

    private static string Display(string? value) => string.IsNullOrWhiteSpace(value) ? "-" : value;

    private static string Secret(string? value, bool reveal)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "-";
        }

        if (reveal)
        {
            return value;
        }

        return value.Length <= 8 ? "********" : value[..4] + "…" + value[^4..];
    }

    private sealed class Options
    {
        private readonly Dictionary<string, string> _values = new(StringComparer.Ordinal);

        public List<string> Positional { get; } = new();

        public string? Get(string name) => _values.TryGetValue(name, out string? value) ? value : null;

        public bool HasFlag(string name) => _values.ContainsKey(name);

        public static Options Parse(string[] args)
        {
            var options = new Options();
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                if (arg.StartsWith('-'))
                {
                    if (i + 1 < args.Length && !args[i + 1].StartsWith('-'))
                    {
                        options._values[arg] = args[++i];
                    }
                    else
                    {
                        options._values[arg] = "true";
                    }
                }
                else
                {
                    options.Positional.Add(arg);
                }
            }

            return options;
        }
    }
}
