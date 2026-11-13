using System;
using System.Collections.Generic;

namespace NpvTunnel.Core.Models;

public sealed class Profile
{
    public Guid Id { get; set; } = Guid.NewGuid();


    public string Name { get; set; } = "Untitled";


    public ProfileProtocol Protocol { get; set; }

    public string Address { get; set; } = string.Empty;


    public int Port { get; set; } = 443;


    public string Uuid { get; set; } = string.Empty;


    public int AlterId { get; set; }

    public string VmessSecurity { get; set; } = "auto";


    public string Password { get; set; } = string.Empty;


    public string Method { get; set; } = string.Empty;


    public string Username { get; set; } = string.Empty;


    public string Flow { get; set; } = string.Empty;


    public Transport Transport { get; set; }

    public string Path { get; set; } = "/";


    public string Host { get; set; } = string.Empty;


    public string ServiceName { get; set; } = string.Empty;


    public IReadOnlyList<string> Alpn { get; set; } = Array.Empty<string>();


    public SecurityLayer Security { get; set; }

    public string Sni { get; set; } = string.Empty;


    public string Fingerprint { get; set; } = string.Empty;


    public string PublicKey { get; set; } = string.Empty;


    public string ShortId { get; set; } = string.Empty;


    public string SpiderX { get; set; } = string.Empty;


    public bool AllowInsecure { get; set; }

    public string DomainStrategy { get; set; } = "UseIP";


    public bool Mux { get; set; }

    public string Fragment { get; set; } = string.Empty;


    public string Source { get; set; } = string.Empty;


    public DateTimeOffset ImportedAt { get; set; } = DateTimeOffset.UtcNow;


    public string Endpoint => $"{Address}:{Port}";

    public Profile Clone()
    {
        return (Profile)MemberwiseClone();
    }

    public override string ToString()
    {
        return $"{Name} [{Protocol} {Endpoint}]";
    }
}
