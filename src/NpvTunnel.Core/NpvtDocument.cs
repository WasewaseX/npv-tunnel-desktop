using System;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using NpvTunnel.Core.Models;

namespace NpvTunnel.Core.Import;

public sealed class NpvtDocument
{
    public const string Schema = "npvt/1";

    private static readonly JsonSerializerOptions Options = new JsonSerializerOptions
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    [JsonPropertyName("schema")]
    public string SchemaVersion { get; set; } = "npvt/1";


    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("protocol")]
    public string Protocol { get; set; } = "vless";


    [JsonPropertyName("address")]
    public string Address { get; set; } = string.Empty;


    [JsonPropertyName("port")]
    public int Port { get; set; } = 443;


    [JsonPropertyName("uuid")]
    public string? Uuid { get; set; }

    [JsonPropertyName("password")]
    public string? Password { get; set; }

    [JsonPropertyName("username")]
    public string? Username { get; set; }

    [JsonPropertyName("method")]
    public string? Method { get; set; }

    [JsonPropertyName("flow")]
    public string? Flow { get; set; }

    [JsonPropertyName("alterId")]
    public int AlterId { get; set; }

    [JsonPropertyName("vmessSecurity")]
    public string? VmessSecurity { get; set; }

    [JsonPropertyName("network")]
    public string? Network { get; set; }

    [JsonPropertyName("path")]
    public string? Path { get; set; }

    [JsonPropertyName("host")]
    public string? Host { get; set; }

    [JsonPropertyName("serviceName")]
    public string? ServiceName { get; set; }

    [JsonPropertyName("alpn")]
    public string[]? Alpn { get; set; }

    [JsonPropertyName("security")]
    public string? Security { get; set; }

    [JsonPropertyName("sni")]
    public string? Sni { get; set; }

    [JsonPropertyName("fp")]
    public string? Fingerprint { get; set; }

    [JsonPropertyName("pbk")]
    public string? PublicKey { get; set; }

    [JsonPropertyName("sid")]
    public string? ShortId { get; set; }

    [JsonPropertyName("spx")]
    public string? SpiderX { get; set; }

    [JsonPropertyName("allowInsecure")]
    public bool AllowInsecure { get; set; }

    [JsonPropertyName("mux")]
    public bool Mux { get; set; }

    [JsonPropertyName("fragment")]
    public string? Fragment { get; set; }

    [JsonPropertyName("domainStrategy")]
    public string? DomainStrategy { get; set; }

    [JsonPropertyName("remarks")]
    public string? Remarks { get; set; }

    public string ToJson()
    {
        return JsonSerializer.Serialize(this, Options);
    }

    public Profile ToProfile()
    {
        ProfileProtocol result;
        ProfileProtocol protocol = (Enum.TryParse<ProfileProtocol>(Protocol, ignoreCase: true, out result) ? result : ProfileProtocol.Vless);
        Transport transport;
        switch ((Network ?? "tcp").ToLowerInvariant())
        {
            case "websocket":
            case "ws":
                transport = Transport.WebSocket;
                break;
            case "grpc":
            case "gun":
                transport = Transport.Grpc;
                break;
            case "httpupgrade":
                transport = Transport.HttpUpgrade;
                break;
            case "splithttp":
            case "xhttp":
                transport = Transport.Xhttp;
                break;
            case "quic":
                transport = Transport.Quic;
                break;
            default:
                transport = Transport.Tcp;
                break;
        }
        Transport transport2 = transport;
        string text = (Security ?? "none").ToLowerInvariant();
        SecurityLayer security = ((text == "tls") ? SecurityLayer.Tls : ((text == "reality") ? SecurityLayer.Reality : SecurityLayer.None));
        return new Profile
        {
            Name = (string.IsNullOrWhiteSpace(Name) ? Address : Name),
            Protocol = protocol,
            Address = Address.Trim(),
            Port = Port,
            Uuid = (Uuid ?? string.Empty),
            Password = (Password ?? string.Empty),
            Username = (Username ?? string.Empty),
            Method = (Method ?? string.Empty),
            Flow = (Flow ?? string.Empty),
            AlterId = AlterId,
            VmessSecurity = (string.IsNullOrWhiteSpace(VmessSecurity) ? "auto" : VmessSecurity),
            Transport = transport2,
            Path = (string.IsNullOrWhiteSpace(Path) ? "/" : Path),
            Host = (Host ?? string.Empty),
            ServiceName = (ServiceName ?? string.Empty),
            Alpn = (Alpn ?? Array.Empty<string>()),
            Security = security,
            Sni = (Sni ?? string.Empty),
            Fingerprint = (Fingerprint ?? string.Empty),
            PublicKey = (PublicKey ?? string.Empty),
            ShortId = (ShortId ?? string.Empty),
            SpiderX = (SpiderX ?? string.Empty),
            AllowInsecure = AllowInsecure,
            Mux = Mux,
            Fragment = (Fragment ?? string.Empty),
            DomainStrategy = (string.IsNullOrWhiteSpace(DomainStrategy) ? "UseIP" : DomainStrategy),
            Source = "npvt/1"
        };
    }

    public static NpvtDocument FromProfile(Profile profile, string? remarks = null)
    {
        NpvtDocument obj = new NpvtDocument
        {
            Name = profile.Name,
            Protocol = profile.Protocol.ToString().ToLowerInvariant(),
            Address = profile.Address,
            Port = profile.Port,
            Uuid = (string.IsNullOrEmpty(profile.Uuid) ? null : profile.Uuid),
            Password = (string.IsNullOrEmpty(profile.Password) ? null : profile.Password),
            Username = (string.IsNullOrEmpty(profile.Username) ? null : profile.Username),
            Method = (string.IsNullOrEmpty(profile.Method) ? null : profile.Method),
            Flow = (string.IsNullOrEmpty(profile.Flow) ? null : profile.Flow),
            AlterId = profile.AlterId,
            VmessSecurity = profile.VmessSecurity
        };
        string network = ((!(profile.Transport.ToString().ToLowerInvariant() == "websocket")) ? profile.Transport.ToString().ToLowerInvariant() : "ws");
        obj.Network = network;
        obj.Path = profile.Path;
        obj.Host = (string.IsNullOrEmpty(profile.Host) ? null : profile.Host);
        obj.ServiceName = (string.IsNullOrEmpty(profile.ServiceName) ? null : profile.ServiceName);
        obj.Alpn = ((profile.Alpn.Count == 0) ? null : profile.Alpn.ToArray());
        obj.Security = profile.Security.ToString().ToLowerInvariant();
        obj.Sni = (string.IsNullOrEmpty(profile.Sni) ? null : profile.Sni);
        obj.Fingerprint = (string.IsNullOrEmpty(profile.Fingerprint) ? null : profile.Fingerprint);
        obj.PublicKey = (string.IsNullOrEmpty(profile.PublicKey) ? null : profile.PublicKey);
        obj.ShortId = (string.IsNullOrEmpty(profile.ShortId) ? null : profile.ShortId);
        obj.SpiderX = (string.IsNullOrEmpty(profile.SpiderX) ? null : profile.SpiderX);
        obj.AllowInsecure = profile.AllowInsecure;
        obj.Mux = profile.Mux;
        obj.Fragment = (string.IsNullOrEmpty(profile.Fragment) ? null : profile.Fragment);
        obj.DomainStrategy = profile.DomainStrategy;
        obj.Remarks = remarks;
        return obj;
    }
}
