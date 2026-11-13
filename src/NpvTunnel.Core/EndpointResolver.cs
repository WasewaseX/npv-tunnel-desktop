using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using NpvTunnel.Core.Models;

namespace NpvTunnel.Core.Security;

/// <summary>
/// What a configuration's hostname actually points at right now.
///
/// The audit refuses literal private addresses, but a hostname can resolve into
/// private space - deliberately (a channel config aimed at your router) or by
/// DNS rebinding. This resolves the endpoint once, classifies every answer, and
/// hands the surviving address to the config builder so the engine dials that
/// address instead of resolving the name a second time.
///
/// The lookup itself is the same one the engine would make when it connects, so
/// it does not add a DNS leak: the endpoint name has to be resolved to be
/// dialled at all. Names that only resolve through the tunnel (some split-DNS
/// setups) fail here and are reported as unverified rather than blocked.
/// </summary>
public static class EndpointResolver
{
    /// <summary>Outcome of resolving one endpoint host.</summary>
    public sealed record Resolution(
        string Host,
        bool IsLiteral,
        bool Resolved,
        IReadOnlyList<IPAddress> PublicAddresses,
        IReadOnlyList<IPAddress> PrivateAddresses,
        string? Failure)
    {
        public bool HasPrivate => PrivateAddresses.Count > 0;

        public static Resolution Literal(string host) =>
            new(host, IsLiteral: true, Resolved: true, Array.Empty<IPAddress>(), Array.Empty<IPAddress>(), null);

        public static Resolution Failed(string host, string reason) =>
            new(host, IsLiteral: false, Resolved: false, Array.Empty<IPAddress>(), Array.Empty<IPAddress>(), reason);
    }

    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(4);

    public static async Task<Resolution> ResolveAsync(string? host, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return Resolution.Failed(string.Empty, "no address");
        }

        string value = host.Trim().Trim('[', ']');

        if (IPAddress.TryParse(value, out IPAddress? literal))
        {
            return new Resolution(value, IsLiteral: true, Resolved: true,
                literal.IsPrivate() ? Array.Empty<IPAddress>() : new[] { literal },
                literal.IsPrivate() ? new[] { literal } : Array.Empty<IPAddress>(),
                null);
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(DefaultTimeout);
        try
        {
            IPAddress[] addresses = await Dns.GetHostAddressesAsync(value, timeout.Token).ConfigureAwait(false);
            return Classify(value, addresses);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Resolution.Failed(value, "the lookup timed out");
        }
        catch (SocketException ex)
        {
            return Resolution.Failed(value, ex.SocketErrorCode == SocketError.HostNotFound
                ? "the name does not resolve from this machine"
                : "the lookup failed (" + ex.SocketErrorCode + ")");
        }
    }

    /// <summary>Blocking variant for the command line, which has no dispatcher to return to.</summary>
    public static Resolution Resolve(string? host) =>
        Task.Run(() => ResolveAsync(host)).GetAwaiter().GetResult();

    public static Resolution Classify(string host, IEnumerable<IPAddress> addresses)
    {
        List<IPAddress> all = addresses
            .Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
            .Distinct()
            .ToList();

        if (all.Count == 0)
        {
            return Resolution.Failed(host, "the lookup returned no usable address");
        }

        List<IPAddress> privateOnes = all.Where(a => a.IsPrivate()).ToList();
        List<IPAddress> publicOnes = all.Where(a => !a.IsPrivate()).ToList();
        return new Resolution(host, IsLiteral: false, Resolved: true, publicOnes, privateOnes, null);
    }

    /// <summary>
    /// The address to pin in the generated config, if there is exactly one sensible
    /// choice. IPv4 is preferred when IPv6 is blocked, and a host whose answers are
    /// all private has no pin at all - that configuration is refused anyway.
    /// </summary>
    public static IPAddress? PinCandidate(Resolution resolution, bool preferIpv4)
    {
        if (!resolution.Resolved || resolution.HasPrivate || resolution.PublicAddresses.Count == 0)
        {
            return null;
        }

        if (preferIpv4)
        {
            IPAddress? v4 = resolution.PublicAddresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (v4 is not null)
            {
                return v4;
            }
        }

        return resolution.PublicAddresses[0];
    }
}

/// <summary>Address classification used by the audit and the resolver.</summary>
public static class AddressScope
{
    /// <summary>
    /// Loopback, RFC1918, CGNAT, link-local, unique-local, multicast, benchmarking and the
    /// documentation ranges. None of them can be the far end of a tunnel a stranger handed
    /// out, so a configuration naming one is broken at best.
    /// </summary>
    public static bool IsPrivate(this IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] b = address.GetAddressBytes();
            return b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
                || (b[0] == 192 && b[1] == 0 && b[2] == 2)
                || (b[0] == 198 && b[1] == 51 && b[2] == 100)
                || (b[0] == 203 && b[1] == 0 && b[2] == 113)
                || (b[0] == 198 && b[1] >= 18 && b[1] <= 19)
                || b[0] == 0
                || b[0] >= 224;
        }

        byte[] v6 = address.GetAddressBytes();
        return address.IsIPv6LinkLocal
            || address.IsIPv6SiteLocal
            || (v6[0] & 0xFE) == 0xFC
            || (v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x0D && v6[3] == 0xB8);
    }
}
