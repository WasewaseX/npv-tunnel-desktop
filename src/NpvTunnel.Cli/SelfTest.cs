using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using NpvTunnel.Core.Engine;
using NpvTunnel.Core.Import;
using NpvTunnel.Core.Models;
using NpvTunnel.Core.Security;
using CoreUriParser = NpvTunnel.Core.Import.UriParser;

namespace NpvTunnel.Cli;

/// <summary>
/// End to end check that runs on the target machine: the importer has to read a
/// container, the builder has to produce a config, the audit has to behave, and
/// the engine (when present) has to accept the result.
/// </summary>
public static class SelfTest
{
    public static int Run(string? enginePath, bool trustCustomEngine = false)
    {
        int failures = 0;
        void Check(string name, Func<bool> test)
        {
            bool ok;
            string detail;
            try
            {
                ok = test();
                detail = ok ? "ok" : "FAILED";
            }
            catch (Exception ex)
            {
                ok = false;
                detail = "threw " + ex.GetType().Name + ": " + ex.Message;
            }

            if (!ok)
            {
                failures++;
            }

            Console.WriteLine($"  [{(ok ? "pass" : "fail")}] {name}{(ok ? string.Empty : " - " + detail)}");
        }

        Console.WriteLine("npvtunnel selftest");

        Check("share link parses", () =>
            CoreUriParser.Parse("vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=ws&path=%2Fws&sni=example.com#Self").Success);

        Check("container decrypts and yields profiles", () =>
        {
            string container = BuildContainer();
            ImportBatch batch = NpvTunnel.Core.Import.NpvtImporter.ImportAll(container);
            return batch.Success && batch.ImportedCount == 2;
        });

        Check("private endpoint is refused", () =>
        {
            var profile = new Profile { Address = "192.168.1.10", Port = 443 };
            return ConfigAudit.BlocksConnect(ConfigAudit.Review(profile));
        });

        Check("allowInsecure never reaches the engine", () =>
        {
            var profile = Sample();
            profile.AllowInsecure = true;
            string json = XrayConfigBuilder.Build(profile, new EngineOptions()).Json;
            return !json.Contains("\"allowInsecure\":true", StringComparison.Ordinal);
        });

        Check("generated config binds loopback only", () =>
        {
            string json = XrayConfigBuilder.Build(Sample(), new EngineOptions { SocksPort = 2080, HttpPort = 2081 }).Json;
            return json.Contains("127.0.0.1", StringComparison.Ordinal)
                && !json.Contains("0.0.0.0", StringComparison.Ordinal);
        });

        Check("redactor hides credentials", () =>
            !Redactor.Scrub("password=hunter2").Contains("hunter2", StringComparison.Ordinal));

        string? engine = enginePath ?? EngineLocator.Find();
        if (engine is null)
        {
            Console.WriteLine("  [skip] engine tests: no xray binary found");
        }
        else
        {
            Check("engine digest verifies", () =>
            {
                using var runner = new EngineRunner(engine);
                return runner.VerifyDigest(out _);
            });

            Check("engine accepts a generated config", () =>
            {
                using var runner = new EngineRunner(engine);
                string path = runner.WriteConfig(Sample(), new EngineOptions { SocksPort = 21080, HttpPort = 21081 });
                return runner.TestConfig(path, out _);
            });
        }

        Console.WriteLine(failures == 0 ? "selftest passed" : $"selftest failed: {failures} check(s)");
        return failures == 0 ? 0 : 1;
    }

    private static Profile Sample() => new()
    {
        Name = "Self test",
        Protocol = ProfileProtocol.Vless,
        Address = "example.com",
        Port = 443,
        Uuid = "11111111-2222-3333-4444-555555555555",
        Transport = Transport.WebSocket,
        Path = "/ws",
        Host = "example.com",
        Security = SecurityLayer.Tls,
        Sni = "example.com",
    };

    /// <summary>Builds a container without shipping a real channel config in the repo.</summary>
    public static string BuildContainer()
    {
        static string Seal(string plaintext)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(plaintext);
            byte[] nonce = RandomNumberGenerator16();
            byte[] payload = new byte[16 + bytes.Length];
            nonce.CopyTo(payload, 0);
            bytes.CopyTo(payload, 16);
            byte[] cipher = NpvtWhitebox.Decrypt(payload);
            cipher.CopyTo(payload, 16);
            return Convert.ToBase64String(payload);
        }

        string wrapper = "[{\"name\":\"Self one\",\"type\":\"V2RAY\",\"v2rayProfile\":{\"remarks\":\"Self one\","
                + "\"server\":\"example.com\",\"serverPort\":\"443\",\"password\":\"11111111-2222-3333-4444-555555555555\","
                + "\"network\":\"ws\",\"security\":\"tls\",\"sni\":\"example.com\",\"v2rayJson\":\"{\\\"remarks\\\":\\\"Self one\\\","
                + "\\\"outbounds\\\":[{\\\"protocol\\\":\\\"vless\\\",\\\"settings\\\":{\\\"vnext\\\":[{\\\"address\\\":\\\"example.com\\\","
                + "\\\"port\\\":443,\\\"users\\\":[{\\\"id\\\":\\\"11111111-2222-3333-4444-555555555555\\\",\\\"encryption\\\":\\\"none\\\"}]}]},"
                + "\\\"streamSettings\\\":{\\\"network\\\":\\\"ws\\\",\\\"security\\\":\\\"tls\\\",\\\"wsSettings\\\":{\\\"path\\\":\\\"/ws\\\"},"
                + "\\\"tlsSettings\\\":{\\\"serverName\\\":\\\"example.com\\\"}}}]}\"}},"
                + "{\"name\":\"Self two\",\"type\":\"V2RAY\",\"v2rayProfile\":{\"remarks\":\"Self two\",\"server\":\"example.net\","
                + "\"serverPort\":\"8443\",\"password\":\"22222222-3333-4444-5555-666666666666\",\"network\":\"grpc\","
                + "\"security\":\"tls\",\"sni\":\"example.net\",\"v2rayJson\":\"{\\\"remarks\\\":\\\"Self two\\\",\\\"outbounds\\\":"
                + "[{\\\"protocol\\\":\\\"vless\\\",\\\"settings\\\":{\\\"vnext\\\":[{\\\"address\\\":\\\"example.net\\\",\\\"port\\\":8443,"
                + "\\\"users\\\":[{\\\"id\\\":\\\"22222222-3333-4444-5555-666666666666\\\",\\\"encryption\\\":\\\"none\\\"}]}]},"
                + "\\\"streamSettings\\\":{\\\"network\\\":\\\"grpc\\\",\\\"security\\\":\\\"tls\\\",\\\"grpcSettings\\\":{\\\"serviceName\\\":\\\"svc\\\"},"
                + "\\\"tlsSettings\\\":{\\\"serverName\\\":\\\"example.net\\\"}}}]}\"}}]";

        return "NPVT1\n" + Seal("1") + "," + Seal(wrapper) + "," + Seal("{\"version\":1,\"isLocked\":true}") + "\n";
    }

    private static byte[] RandomNumberGenerator16()
    {
        byte[] nonce = new byte[16];
        System.Security.Cryptography.RandomNumberGenerator.Fill(nonce);
        return nonce;
    }
}
