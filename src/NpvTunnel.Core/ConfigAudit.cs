using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using NpvTunnel.Core.Models;

namespace NpvTunnel.Core.Security;

/// <summary>
/// Reviews an imported configuration before it is trusted. Public-channels configs
/// are arbitrary input from strangers: this reports what is unusual about one and
/// refuses the few things that should never reach the engine.
/// </summary>
public static class ConfigAudit
{
    public enum Severity
    {
        Info,
        Warning,
        Refused,
    }

    public sealed record Finding(Severity Severity, string Message);

    /// <summary>
    /// Audits a profile. <c>Refused</c> means the profile must not be connected and
    /// never reaches the engine; the profile is still importable so the user can see
    /// it and read the reason.
    /// </summary>
    public static IReadOnlyList<Finding> Review(Profile profile) => Review(profile, resolution: null);

    /// <summary>
    /// Same review, with what the endpoint hostname actually resolves to. A literal
    /// address is checked on its own; a hostname can only be judged once it has been
    /// resolved, which is why connecting resolves it first and refuses private
    /// answers instead of trusting the name.
    /// </summary>
    public static IReadOnlyList<Finding> Review(Profile profile, EndpointResolver.Resolution? resolution)
    {
        var findings = new List<Finding>();

        if (IsPrivateEndpoint(profile.Address))
        {
            findings.Add(new Finding(
                Severity.Refused,
                $"'{profile.Address}' is a private, loopback or link-local address. A public configuration that points at your own network is either broken or trying to reach something inside it."));
        }

        if (resolution is not null && !resolution.IsLiteral)
        {
            if (resolution.HasPrivate)
            {
                string addresses = string.Join(", ", resolution.PrivateAddresses);
                findings.Add(new Finding(
                    Severity.Refused,
                    $"'{resolution.Host}' resolves to {addresses}, which is inside a private or link-local range. A public configuration whose hostname points back into your network is either broken or an attempt to reach something on it, and DNS can be changed after the config was shared."));
            }
            else if (!resolution.Resolved)
            {
                findings.Add(new Finding(
                    Severity.Warning,
                    $"'{resolution.Host}' could not be resolved from this machine ({resolution.Failure}), so it has not been checked against private addresses. The tunnel will resolve it at connect time."));
            }
        }

        bool encrypted = profile.Security is SecurityLayer.Tls or SecurityLayer.Reality;
        if (!encrypted && profile.Protocol == ProfileProtocol.Vless && !IsPrivateEndpoint(profile.Address))
        {
            // VLESS carries no encryption of its own. The engine refuses this
            // combination against a public server, and running it would expose
            // everything on the path regardless.
            findings.Add(new Finding(
                Severity.Refused,
                "VLESS without TLS (or REALITY) cannot run against a public server: the engine refuses it and the traffic would be readable by anyone on the path. Ask the provider for a TLS or REALITY configuration."));
        }
        else if (!encrypted && profile.Protocol is ProfileProtocol.Vless or ProfileProtocol.Vmess or ProfileProtocol.Trojan)
        {
            findings.Add(new Finding(
                Severity.Warning,
                "This configuration has no TLS layer, so the connection can be read and modified by anything on the path."));
        }

        if (profile.AllowInsecure)
        {
            findings.Add(new Finding(
                Severity.Warning,
                "The configuration asked to accept invalid TLS certificates. This build ignores that request."));
        }

        if (string.IsNullOrWhiteSpace(profile.Sni) && encrypted && profile.Security == SecurityLayer.Tls)
        {
            findings.Add(new Finding(
                Severity.Info,
                "No SNI is set on a TLS configuration; some networks treat that as suspicious traffic."));
        }

        if (profile.Security == SecurityLayer.Reality && string.IsNullOrWhiteSpace(profile.PublicKey))
        {
            findings.Add(new Finding(
                Severity.Refused,
                "The configuration claims REALITY but carries no public key, so the handshake cannot be authenticated."));
        }

        if (profile.Port is 0 or > 65535)
        {
            findings.Add(new Finding(Severity.Refused, "The port is outside 1-65535."));
        }
        else if (profile.Port is not (443 or 8443 or 2053 or 2083 or 2087 or 2096))
        {
            findings.Add(new Finding(
                Severity.Info,
                $"Port {profile.Port.ToString(CultureInfo.InvariantCulture)} is uncommon for proxied TLS; some networks block it."));
        }

        if (!string.IsNullOrEmpty(profile.Fragment))
        {
            findings.Add(new Finding(
                Severity.Info,
                "The configuration uses TLS fragmentation. It is kept, but it costs throughput."));
        }

        if (profile.Mux)
        {
            findings.Add(new Finding(
                Severity.Info,
                "Multiplexing is enabled by the author of this configuration, which shares one connection for all traffic."));
        }

        return findings;
    }

    /// <summary>True when any finding must block a connection.</summary>
    public static bool BlocksConnect(IReadOnlyList<Finding> findings)
    {
        foreach (Finding finding in findings)
        {
            if (finding.Severity == Severity.Refused)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Loopback, RFC1918, carrier-grade NAT, link-local and unique-local literals.
    /// A hostname is not judged here - use <see cref="EndpointResolver"/> for that,
    /// because a name can resolve anywhere and the answer can change after the
    /// configuration was shared.
    /// </summary>
    public static bool IsPrivateEndpoint(string? host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        return IPAddress.TryParse(host.Trim().Trim('[', ']'), out IPAddress? address) && address.IsPrivate();
    }
}
