using System;
using System.Collections.Generic;
using System.Text.Json;
using NpvTunnel.Core.Models;
using NpvTunnel.Core.Security;

namespace NpvTunnel.Core.Import;

/// <summary>
/// Turns the payloads of a vendor <c>.npvt</c> container into profiles.
/// </summary>
/// <remarks>
/// The profile block is a JSON array of wrappers:
/// <code>
/// [ { "name": "...", "type": "V2RAY",
///     "v2rayProfile": { "server": "...", "serverPort": "443", "password": "&lt;uuid&gt;",
///                       "network": "ws", "security": "tls", "sni": "...",
///                       "v2rayJson": "{ ...full Xray client config as a string... }" } } ]
/// </code>
/// The nested <c>v2rayJson</c> is the authoritative one when it is present - it is
/// a complete client config, so the outbound and stream settings are read from it
/// and the flat fields are only a fallback. Only the outbound is ever taken from
/// it: inbounds, routing rules and anything else stay untouched, so a hostile
/// config cannot ask this app to open a listener or reroute traffic.
/// </remarks>
public static class NpvConfigReader
{
    /// <summary>Parses one decrypted payload. Returns an empty list when it holds no profiles.</summary>
    public static IReadOnlyList<Profile> ReadPayload(string payload, List<string> warnings)
    {
        var profiles = new List<Profile>();
        string trimmed = payload.Trim();
        if (trimmed.Length == 0)
        {
            return profiles;
        }

        JsonDocument document;
        try
        {
            document = SafeJson.Parse(trimmed);
        }
        catch (Exception ex) when (ex is JsonException or SafeJson.JsonTooLargeException or SafeJson.JsonStructureException)
        {
            warnings.Add("A block inside the container is not valid JSON and was skipped.");
            return profiles;
        }

        using (document)
        {
            JsonElement root = document.RootElement;
            switch (root.ValueKind)
            {
                case JsonValueKind.Array:
                    foreach (JsonElement wrapper in root.EnumerateArray())
                    {
                        if (wrapper.ValueKind != JsonValueKind.Object)
                        {
                            continue;
                        }

                        AddWrapper(profiles, wrapper, warnings);
                    }

                    break;

                case JsonValueKind.Object:
                    // The lockConfig block is an object without a profile in it.
                    AddWrapper(profiles, root, warnings);
                    break;
            }
        }

        return profiles;
    }

    private static void AddWrapper(List<Profile> profiles, JsonElement wrapper, List<string> warnings)
    {
        if (!wrapper.TryGetProperty("v2rayProfile", out JsonElement v2ray) || v2ray.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        string name =
            FirstString(wrapper, "name")
            ?? FirstString(v2ray, "remarks")
            ?? "Imported configuration";

        Profile? profile = ReadFromV2rayJson(v2ray, warnings) ?? ReadFromFlatFields(v2ray);
        if (profile is null)
        {
            warnings.Add($"'{name}' was skipped: it has no usable server address.");
            return;
        }

        if (string.IsNullOrWhiteSpace(profile.Name))
        {
            profile.Name = name;
        }

        profiles.Add(profile);
    }

    private static Profile? ReadFromV2rayJson(JsonElement v2ray, List<string> warnings)
    {
        string? inner = FirstString(v2ray, "v2rayJson");
        if (string.IsNullOrWhiteSpace(inner))
        {
            return null;
        }

        JsonDocument document;
        try
        {
            document = SafeJson.Parse(inner);
        }
        catch (Exception ex) when (ex is JsonException or SafeJson.JsonTooLargeException or SafeJson.JsonStructureException)
        {
            return null;
        }

        using (document)
        {
            if (!document.RootElement.TryGetProperty("outbounds", out JsonElement outbounds)
                || outbounds.ValueKind != JsonValueKind.Array
                || outbounds.GetArrayLength() == 0)
            {
                return null;
            }

            JsonElement outbound = outbounds[0];
            string protocol = FirstString(outbound, "protocol") ?? string.Empty;

            var profile = new Profile
            {
                Protocol = MapProtocol(protocol),
                Name = FirstString(document.RootElement, "remarks") ?? FirstString(v2ray, "remarks") ?? string.Empty,
            };

            ApplyServer(profile, outbound, protocol, warnings);
            ApplyStream(profile, outbound);

            if (outbound.TryGetProperty("mux", out JsonElement mux)
                && mux.ValueKind == JsonValueKind.Object
                && mux.TryGetProperty("enabled", out JsonElement enabled)
                && enabled.ValueKind == JsonValueKind.True)
            {
                profile.Mux = true;
            }

            return string.IsNullOrWhiteSpace(profile.Address) ? null : profile;
        }
    }

    private static void ApplyServer(Profile profile, JsonElement outbound, string protocol, List<string> warnings)
    {
        if (!outbound.TryGetProperty("settings", out JsonElement settings) || settings.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        if (settings.TryGetProperty("vnext", out JsonElement vnext)
            && vnext.ValueKind == JsonValueKind.Array
            && vnext.GetArrayLength() > 0)
        {
            JsonElement server = vnext[0];
            profile.Address = FirstString(server, "address") ?? string.Empty;
            profile.Port = ReadPort(server) ?? 443;

            if (server.TryGetProperty("users", out JsonElement users)
                && users.ValueKind == JsonValueKind.Array
                && users.GetArrayLength() > 0)
            {
                JsonElement user = users[0];
                profile.Uuid = FirstString(user, "id") ?? string.Empty;
                profile.Flow = FirstString(user, "flow") ?? string.Empty;
                profile.VmessSecurity = FirstString(user, "security") ?? "auto";
                if (profile.Protocol == ProfileProtocol.Shadowsocks)
                {
                    profile.Method = FirstString(user, "encryption") ?? string.Empty;
                }
            }

            return;
        }

        if (settings.TryGetProperty("servers", out JsonElement servers)
            && servers.ValueKind == JsonValueKind.Array
            && servers.GetArrayLength() > 0)
        {
            JsonElement server = servers[0];
            profile.Address = FirstString(server, "address") ?? string.Empty;
            profile.Port = ReadPort(server) ?? 443;
            profile.Password = FirstString(server, "password") ?? string.Empty;
            profile.Method = FirstString(server, "method") ?? profile.Method;
            profile.Username = FirstString(server, "user") ?? string.Empty;

            if (string.IsNullOrEmpty(profile.Method)
                && server.TryGetProperty("users", out JsonElement ssUsers)
                && ssUsers.ValueKind == JsonValueKind.Array
                && ssUsers.GetArrayLength() > 0)
            {
                // Shadowsocks 2022 puts the credential in a users array instead.
                profile.Method = FirstString(ssUsers[0], "method") ?? string.Empty;
                profile.Password = FirstString(ssUsers[0], "password") ?? profile.Password;
            }

            return;
        }

        profile.Address = FirstString(settings, "address") ?? string.Empty;
        profile.Port = ReadPort(settings) ?? 1080;
        if (protocol is "socks" or "http")
        {
            if (settings.TryGetProperty("servers", out JsonElement list)
                && list.ValueKind == JsonValueKind.Array
                && list.GetArrayLength() > 0)
            {
                profile.Username = FirstString(list[0], "user") ?? string.Empty;
                profile.Password = FirstString(list[0], "pass") ?? string.Empty;
            }
        }

        if (string.IsNullOrWhiteSpace(profile.Address))
        {
            warnings.Add("An outbound was skipped because it has no server address.");
        }
    }

    private static void ApplyStream(Profile profile, JsonElement outbound)
    {
        if (!outbound.TryGetProperty("streamSettings", out JsonElement stream) || stream.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        profile.Transport = MapTransport(FirstString(stream, "network"));
        profile.Security = MapSecurity(FirstString(stream, "security"));

        if (stream.TryGetProperty("wsSettings", out JsonElement ws) && ws.ValueKind == JsonValueKind.Object)
        {
            profile.Path = FirstString(ws, "path") ?? profile.Path;
            profile.Host = ReadHeaderHost(ws) ?? profile.Host;
        }

        if (stream.TryGetProperty("grpcSettings", out JsonElement grpc) && grpc.ValueKind == JsonValueKind.Object)
        {
            profile.ServiceName = FirstString(grpc, "serviceName") ?? profile.ServiceName;
            profile.Host = FirstString(grpc, "authority") ?? profile.Host;
        }

        if (stream.TryGetProperty("xhttpSettings", out JsonElement xhttp) && xhttp.ValueKind == JsonValueKind.Object)
        {
            profile.Path = FirstString(xhttp, "path") ?? profile.Path;
            profile.Host = FirstString(xhttp, "host") ?? profile.Host;
        }

        if (stream.TryGetProperty("httpupgradeSettings", out JsonElement upgrade) && upgrade.ValueKind == JsonValueKind.Object)
        {
            profile.Path = FirstString(upgrade, "path") ?? profile.Path;
            profile.Host = FirstString(upgrade, "host") ?? profile.Host;
        }

        if (stream.TryGetProperty("tcpSettings", out JsonElement tcp)
            && tcp.ValueKind == JsonValueKind.Object
            && tcp.TryGetProperty("header", out JsonElement header)
            && header.ValueKind == JsonValueKind.Object
            && string.Equals(FirstString(header, "type"), "http", StringComparison.OrdinalIgnoreCase)
            && header.TryGetProperty("request", out JsonElement request)
            && request.ValueKind == JsonValueKind.Object)
        {
            if (request.TryGetProperty("path", out JsonElement path)
                && path.ValueKind == JsonValueKind.Array
                && path.GetArrayLength() > 0)
            {
                profile.Path = path[0].GetString() ?? profile.Path;
            }

            profile.Host = ReadHeaderHost(request) ?? profile.Host;
        }

        if (stream.TryGetProperty("tlsSettings", out JsonElement tls) && tls.ValueKind == JsonValueKind.Object)
        {
            profile.Sni = FirstString(tls, "serverName") ?? profile.Sni;
            profile.Fingerprint = FirstString(tls, "fingerprint") ?? profile.Fingerprint;
            profile.Alpn = ReadAlpn(tls) ?? profile.Alpn;
            profile.AllowInsecure = tls.TryGetProperty("allowInsecure", out JsonElement insecure)
                                    && insecure.ValueKind == JsonValueKind.True;
        }

        if (stream.TryGetProperty("realitySettings", out JsonElement reality) && reality.ValueKind == JsonValueKind.Object)
        {
            profile.Security = SecurityLayer.Reality;
            profile.Sni = FirstString(reality, "serverName") ?? profile.Sni;
            profile.Fingerprint = FirstString(reality, "fingerprint") ?? profile.Fingerprint;
            profile.PublicKey = FirstString(reality, "publicKey") ?? profile.PublicKey;
            profile.ShortId = FirstString(reality, "shortId") ?? profile.ShortId;
            profile.SpiderX = FirstString(reality, "spiderX") ?? profile.SpiderX;
        }
    }

    /// <summary>Fallback for wrappers whose nested config is missing or stripped.</summary>
    private static Profile? ReadFromFlatFields(JsonElement v2ray)
    {
        string server = FirstString(v2ray, "server") ?? string.Empty;
        if (string.IsNullOrWhiteSpace(server))
        {
            return null;
        }

        var profile = new Profile
        {
            Name = FirstString(v2ray, "remarks") ?? string.Empty,
            Address = server,
            Port = ReadPort(v2ray) ?? 443,
            Password = FirstString(v2ray, "password") ?? string.Empty,
            Method = FirstString(v2ray, "method") ?? string.Empty,
            Sni = FirstString(v2ray, "sni") ?? string.Empty,
            Host = FirstString(v2ray, "host") ?? string.Empty,
            Transport = MapTransport(FirstString(v2ray, "network")),
            Security = MapSecurity(FirstString(v2ray, "security")),
            AllowInsecure = v2ray.TryGetProperty("insecure", out JsonElement insecure)
                            && insecure.ValueKind == JsonValueKind.True,
        };

        // The flat fields do not say which protocol it is; a UUID-shaped password
        // with a TLS-ish transport is VLESS in every sample of this format seen so far.
        profile.Protocol = profile.Security == SecurityLayer.None ? ProfileProtocol.Vmess : ProfileProtocol.Vless;
        profile.Uuid = profile.Password;
        return profile;
    }

    private static ProfileProtocol MapProtocol(string protocol) => protocol.ToLowerInvariant() switch
    {
        "vless" => ProfileProtocol.Vless,
        "vmess" => ProfileProtocol.Vmess,
        "trojan" => ProfileProtocol.Trojan,
        "shadowsocks" or "ss" => ProfileProtocol.Shadowsocks,
        "socks" or "socks5" => ProfileProtocol.Socks,
        "http" or "https" => ProfileProtocol.Http,
        "hysteria2" or "hy2" => ProfileProtocol.Hysteria2,
        "wireguard" => ProfileProtocol.WireGuard,
        _ => ProfileProtocol.Vless,
    };

    private static Transport MapTransport(string? network) => network?.ToLowerInvariant() switch
    {
        "ws" or "websocket" => Transport.WebSocket,
        "grpc" or "gun" => Transport.Grpc,
        "httpupgrade" => Transport.HttpUpgrade,
        "xhttp" or "splithttp" => Transport.Xhttp,
        "quic" => Transport.Quic,
        _ => Transport.Tcp,
    };

    private static SecurityLayer MapSecurity(string? security) => security?.ToLowerInvariant() switch
    {
        "tls" or "xtls" => SecurityLayer.Tls,
        "reality" => SecurityLayer.Reality,
        _ => SecurityLayer.None,
    };

    private static string? ReadHeaderHost(JsonElement element)
    {
        if (!element.TryGetProperty("headers", out JsonElement headers) || headers.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (headers.TryGetProperty("Host", out JsonElement host))
        {
            return host.ValueKind switch
            {
                JsonValueKind.String => host.GetString(),
                JsonValueKind.Array when host.GetArrayLength() > 0 => host[0].GetString(),
                _ => null,
            };
        }

        return null;
    }

    private static IReadOnlyList<string>? ReadAlpn(JsonElement tls)
    {
        if (!tls.TryGetProperty("alpn", out JsonElement alpn) || alpn.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var values = new List<string>();
        foreach (JsonElement item in alpn.EnumerateArray())
        {
            string? value = item.GetString();
            if (!string.IsNullOrWhiteSpace(value))
            {
                values.Add(value);
            }
        }

        return values.Count == 0 ? null : values;
    }

    private static string? FirstString(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out JsonElement value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.GetRawText(),
            _ => null,
        };
    }

    private static int? ReadPort(JsonElement element)
    {
        if (!element.TryGetProperty("port", out JsonElement port))
        {
            port = element.TryGetProperty("serverPort", out JsonElement flat) ? flat : default;
        }

        return port.ValueKind switch
        {
            JsonValueKind.Number when port.TryGetInt32(out int number) => number,
            JsonValueKind.String when int.TryParse(port.GetString(), out int parsed) => parsed,
            _ => null,
        };
    }
}
