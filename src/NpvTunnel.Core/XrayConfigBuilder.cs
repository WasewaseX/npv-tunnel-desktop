using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using NpvTunnel.Core.Models;

namespace NpvTunnel.Core.Engine;

public static class XrayConfigBuilder
{
    public static EngineConfig Build(Profile profile, EngineOptions options)
    {
        ArgumentNullException.ThrowIfNull(profile, "profile");
        ArgumentNullException.ThrowIfNull(options, "options");
        options.Validate();
        List<string> list = new List<string>();
        if (profile.AllowInsecure)
        {
            list.Add("TLS certificate verification is DISABLED for this profile.");
        }
        if (!options.LocalOnly)
        {
            list.Add("The local proxy is listening on all interfaces without authentication.");
        }
        if ((uint)(profile.Protocol - 6) <= 1u)
        {
            throw new NotSupportedException($"{profile.Protocol} needs the sing-box engine. Switch the profile to a VLESS/VMess/Trojan/Shadowsocks " + "server, or install the sing-box core from Settings → Engine.");
        }
        JsonObject jsonObject = new JsonObject();
        jsonObject["log"] = new JsonObject
        {
            ["loglevel"] = NormaliseLogLevel(options.LogLevel),
            ["access"] = "none",
            ["error"] = ""
        };
        jsonObject["inbounds"] = new JsonArray(BuildSocksInbound(options), BuildHttpInbound(options));
        jsonObject["outbounds"] = new JsonArray(BuildProxyOutbound(profile, options, list), BuildDirect(), BuildBlock());
        jsonObject["routing"] = BuildRouting(options, list);
        jsonObject["dns"] = BuildDns(options);
        JsonObject jsonObject2 = jsonObject;
        if (profile.Mux)
        {
            jsonObject2["policy"] = new JsonObject { ["levels"] = new JsonObject { ["0"] = new JsonObject
            {
                ["handshake"] = 4,
                ["connIdle"] = 300
            } } };
        }
        string json = jsonObject2.ToJsonString(new JsonSerializerOptions
        {
            WriteIndented = true
        });
        return new EngineConfig
        {
            Json = json,
            Warnings = list
        };
    }

    private static JsonObject BuildSocksInbound(EngineOptions o)
    {
        JsonObject jsonObject = new JsonObject();
        jsonObject["tag"] = "npvt-socks";
        jsonObject["listen"] = (o.LocalOnly ? "127.0.0.1" : "0.0.0.0");
        jsonObject["port"] = o.SocksPort;
        jsonObject["protocol"] = "socks";
        jsonObject["settings"] = new JsonObject
        {
            ["auth"] = "noauth",
            ["udp"] = !o.BlockQuic
        };
        jsonObject["sniffing"] = new JsonObject
        {
            ["enabled"] = true,
            ["destOverride"] = new JsonArray("http", "tls", "quic"),
            ["routeOnly"] = true
        };
        return jsonObject;
    }

    private static JsonObject BuildHttpInbound(EngineOptions o)
    {
        JsonObject jsonObject = new JsonObject();
        jsonObject["tag"] = "npvt-http";
        jsonObject["listen"] = (o.LocalOnly ? "127.0.0.1" : "0.0.0.0");
        jsonObject["port"] = o.HttpPort;
        jsonObject["protocol"] = "http";
        jsonObject["settings"] = new JsonObject { ["timeout"] = 300 };
        jsonObject["sniffing"] = new JsonObject
        {
            ["enabled"] = true,
            ["destOverride"] = new JsonArray("http", "tls"),
            ["routeOnly"] = true
        };
        return jsonObject;
    }

    private static JsonObject BuildProxyOutbound(Profile p, EngineOptions o, List<string> warnings)
    {
        JsonObject value = BuildStreamSettings(p, warnings);
        JsonObject jsonObject = new JsonObject
        {
            ["tag"] = "proxy",
            ["protocol"] = ProtocolName(p.Protocol),
            ["settings"] = BuildProtocolSettings(p),
            ["streamSettings"] = value
        };
        if (o.EnableMux || p.Mux)
        {
            jsonObject["mux"] = new JsonObject
            {
                ["enabled"] = true,
                ["concurrency"] = 8,
                ["xudpConcurrency"] = 16,
                ["xudpProxyUDP443"] = (o.BlockQuic ? "reject" : "allow")
            };
        }
        return jsonObject;
    }

    private static string ProtocolName(ProfileProtocol protocol)
    {
        return protocol switch
        {
            ProfileProtocol.Vless => "vless",
            ProfileProtocol.Vmess => "vmess",
            ProfileProtocol.Trojan => "trojan",
            ProfileProtocol.Shadowsocks => "shadowsocks",
            ProfileProtocol.Socks => "socks",
            ProfileProtocol.Http => "http",
            _ => throw new NotSupportedException($"Protocol {protocol} is not supported by the Xray engine."),
        };
    }

    private static JsonObject BuildProtocolSettings(Profile p)
    {
        switch (p.Protocol)
        {
        case ProfileProtocol.Vless:
        {
            JsonObject jsonObject3 = new JsonObject
            {
                ["id"] = p.Uuid,
                ["encryption"] = "none"
            };
            if (!string.IsNullOrWhiteSpace(p.Flow))
            {
                jsonObject3["flow"] = p.Flow;
            }
            JsonObject jsonObject4 = new JsonObject();
            jsonObject4["vnext"] = new JsonArray(new JsonObject
            {
                ["address"] = p.Address,
                ["port"] = p.Port,
                ["users"] = new JsonArray(jsonObject3)
            });
            return jsonObject4;
        }
        case ProfileProtocol.Vmess:
        {
            JsonObject jsonObject5 = new JsonObject();
            jsonObject5["vnext"] = new JsonArray(new JsonObject
            {
                ["address"] = p.Address,
                ["port"] = p.Port,
                ["users"] = new JsonArray(new JsonObject
                {
                    ["id"] = p.Uuid,
                    ["alterId"] = p.AlterId,
                    ["security"] = (string.IsNullOrWhiteSpace(p.VmessSecurity) ? "auto" : p.VmessSecurity)
                })
            });
            return jsonObject5;
        }
        case ProfileProtocol.Trojan:
        {
            JsonObject jsonObject7 = new JsonObject();
            jsonObject7["servers"] = new JsonArray(new JsonObject
            {
                ["address"] = p.Address,
                ["port"] = p.Port,
                ["password"] = p.Password
            });
            return jsonObject7;
        }
        case ProfileProtocol.Shadowsocks:
        {
            JsonObject jsonObject6 = new JsonObject();
            jsonObject6["servers"] = new JsonArray(new JsonObject
            {
                ["address"] = p.Address,
                ["port"] = p.Port,
                ["method"] = p.Method,
                ["password"] = p.Password,
                ["uot"] = true
            });
            return jsonObject6;
        }
        case ProfileProtocol.Socks:
        case ProfileProtocol.Http:
        {
            JsonObject jsonObject = new JsonObject
            {
                ["address"] = p.Address,
                ["port"] = p.Port
            };
            if (!string.IsNullOrEmpty(p.Username))
            {
                jsonObject["users"] = new JsonArray(new JsonObject
                {
                    ["user"] = p.Username,
                    ["pass"] = p.Password
                });
            }
            JsonObject jsonObject2 = new JsonObject();
            jsonObject2["servers"] = new JsonArray(jsonObject);
            return jsonObject2;
        }
        default:
            throw new NotSupportedException($"Protocol {p.Protocol} is not supported.");
        }
    }

    private static JsonObject BuildStreamSettings(Profile p, List<string> warnings)
    {
        JsonObject jsonObject = new JsonObject();
        jsonObject["network"] = NetworkName(p.Transport);
        JsonObject jsonObject2 = jsonObject;
        jsonObject2["security"] = p.Security switch
        {
            SecurityLayer.Tls => "tls",
            SecurityLayer.Reality => "reality",
            _ => "none",
        };
        JsonObject jsonObject3 = jsonObject;
        switch (p.Transport)
        {
        case Transport.WebSocket:
            jsonObject3["wsSettings"] = new JsonObject
            {
                ["path"] = (string.IsNullOrWhiteSpace(p.Path) ? "/" : p.Path),
                ["headers"] = new JsonObject { ["Host"] = (string.IsNullOrWhiteSpace(p.Host) ? p.Sni : p.Host) }
            };
            break;
        case Transport.Grpc:
            jsonObject3["grpcSettings"] = new JsonObject
            {
                ["serviceName"] = p.ServiceName,
                ["multiMode"] = false
            };
            break;
        case Transport.HttpUpgrade:
            jsonObject3["httpupgradeSettings"] = new JsonObject
            {
                ["path"] = (string.IsNullOrWhiteSpace(p.Path) ? "/" : p.Path),
                ["host"] = (string.IsNullOrWhiteSpace(p.Host) ? p.Sni : p.Host)
            };
            break;
        case Transport.Xhttp:
            jsonObject3["xhttpSettings"] = new JsonObject
            {
                ["path"] = (string.IsNullOrWhiteSpace(p.Path) ? "/" : p.Path),
                ["host"] = (string.IsNullOrWhiteSpace(p.Host) ? p.Sni : p.Host),
                ["mode"] = "auto"
            };
            break;
        case Transport.Quic:
            jsonObject3["quicSettings"] = new JsonObject
            {
                ["security"] = "none",
                ["key"] = "",
                ["header"] = new JsonObject { ["type"] = "none" }
            };
            break;
        }
        if (p.Security == SecurityLayer.Tls)
        {
            JsonObject jsonObject4 = new JsonObject
            {
                ["serverName"] = (string.IsNullOrWhiteSpace(p.Sni) ? p.Address : p.Sni),
                ["allowInsecure"] = p.AllowInsecure
            };
            if (p.Alpn.Count > 0)
            {
                jsonObject4["alpn"] = new JsonArray(((IEnumerable<string>)p.Alpn).Select((Func<string, JsonNode>)((string a) => a)).ToArray());
            }
            if (!string.IsNullOrWhiteSpace(p.Fingerprint))
            {
                jsonObject4["fingerprint"] = p.Fingerprint;
            }
            jsonObject3["tlsSettings"] = jsonObject4;
        }
        else if (p.Security == SecurityLayer.Reality)
        {
            JsonObject value = new JsonObject
            {
                ["serverName"] = p.Sni,
                ["fingerprint"] = (string.IsNullOrWhiteSpace(p.Fingerprint) ? "chrome" : p.Fingerprint),
                ["publicKey"] = p.PublicKey,
                ["shortId"] = p.ShortId,
                ["spiderX"] = (string.IsNullOrWhiteSpace(p.SpiderX) ? "/" : p.SpiderX)
            };
            jsonObject3["realitySettings"] = value;
        }
        JsonObject jsonObject5 = new JsonObject
        {
            ["domainStrategy"] = (string.IsNullOrWhiteSpace(p.DomainStrategy) ? "UseIP" : p.DomainStrategy),
            ["tcpFastOpen"] = true,
            ["tcpNoDelay"] = true,
            ["tcpKeepAliveInterval"] = 15
        };
        if (!string.IsNullOrWhiteSpace(p.Fragment))
        {
            string[] array = p.Fragment.Split(',', StringSplitOptions.TrimEntries);
            jsonObject5["fragment"] = new JsonObject
            {
                ["packets"] = ((array.Length != 0 && array[0].Length > 0) ? array[0] : "tlshello"),
                ["length"] = ((array.Length > 1) ? array[1] : "100-200"),
                ["interval"] = ((array.Length > 2) ? array[2] : "10")
            };
        }
        jsonObject3["sockopt"] = jsonObject5;
        return jsonObject3;
    }

    private static string NetworkName(Transport transport)
    {
        return transport switch
        {
            Transport.Tcp => "tcp",
            Transport.WebSocket => "ws",
            Transport.Grpc => "grpc",
            Transport.HttpUpgrade => "httpupgrade",
            Transport.Xhttp => "xhttp",
            Transport.Quic => "quic",
            _ => "tcp",
        };
    }

    private static JsonObject BuildDirect()
    {
        return new JsonObject
        {
            ["tag"] = "direct",
            ["protocol"] = "freedom",
            ["settings"] = new JsonObject { ["domainStrategy"] = "UseIP" }
        };
    }

    private static JsonObject BuildBlock()
    {
        return new JsonObject
        {
            ["tag"] = "block",
            ["protocol"] = "blackhole",
            ["settings"] = new JsonObject()
        };
    }

    private static JsonObject BuildRouting(EngineOptions o, List<string> warnings)
    {
        JsonArray jsonArray = new JsonArray();
        if (o.BlockBitTorrent)
        {
            jsonArray.Add(new JsonObject
            {
                ["type"] = "field",
                ["protocol"] = new JsonArray("bittorrent"),
                ["outboundTag"] = "block"
            });
        }
        if (o.BlockIpv6)
        {
            jsonArray.Add(new JsonObject
            {
                ["type"] = "field",
                ["ip"] = new JsonArray("::/0"),
                ["outboundTag"] = "block"
            });
        }
        if (o.BlockQuic)
        {
            jsonArray.Add(new JsonObject
            {
                ["type"] = "field",
                ["network"] = "udp",
                ["port"] = 443,
                ["outboundTag"] = "block"
            });
            warnings.Add("QUIC (UDP/443) is blocked so browsers use TCP through the proxy.");
        }
        if (o.BypassLan)
        {
            jsonArray.Add(new JsonObject
            {
                ["type"] = "field",
                ["ip"] = new JsonArray("geoip:private"),
                ["outboundTag"] = "direct"
            });
        }
        jsonArray.Add(new JsonObject
        {
            ["type"] = "field",
            ["inboundTag"] = new JsonArray("npvt-socks", "npvt-http"),
            ["outboundTag"] = "proxy"
        });
        return new JsonObject
        {
            ["domainStrategy"] = "IPIfNonMatch",
            ["rules"] = jsonArray
        };
    }

    private static JsonObject BuildDns(EngineOptions o)
    {
        JsonObject jsonObject = new JsonObject();
        jsonObject["servers"] = new JsonArray(new JsonObject
        {
            ["address"] = (string.IsNullOrWhiteSpace(o.DnsServer) ? "https+local://1.1.1.1/dns-query" : o.DnsServer),
            ["skipFallback"] = false
        }, "localhost");
        jsonObject["queryStrategy"] = (o.BlockIpv6 ? "UseIPv4" : "UseIP");
        jsonObject["disableFallback"] = true;
        return jsonObject;
    }

    private static string NormaliseLogLevel(string level)
    {
        switch (level.ToLowerInvariant())
        {
        case "debug":
        case "info":
        case "warning":
        case "error":
        case "none":
            return level.ToLowerInvariant();
        default:
            return "warning";
        }
    }
}
