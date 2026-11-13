using System.Net;
using System.Text.RegularExpressions;

namespace NpvTunnel.Core.Security;

/// <summary>Field-level validation for anything that reaches the engine config.</summary>
public static class Validators
{
    // A label may not start or end with a hyphen, and may not be empty.
    private static readonly Regex DnsLabel = new(
        "^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$", RegexOptions.Compiled);

    private static readonly Regex ShortIdRegex = new("^[0-9a-fA-F]{0,16}$", RegexOptions.Compiled);

    private static readonly Regex RealityKeyRegex = new("^[A-Za-z0-9_+/=-]{20,120}$", RegexOptions.Compiled);

    private static readonly Regex PathRegex = new(
        "^[A-Za-z0-9._~!$&'()*+,;=:@%/?-]{0,512}$", RegexOptions.Compiled);

    /// <summary>
    /// Hostnames, IPv4 and IPv6 literals only. Blocks whitespace, quotes, pipes,
    /// semicolons and shell metacharacters so a config can never influence a
    /// command line or an INI/registry value it does not belong in.
    /// </summary>
    public static bool IsSafeHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host) || host.Length > 253)
        {
            return false;
        }

        if (IPAddress.TryParse(host, out _))
        {
            return true;
        }

        if (!host.Contains('.'))
        {
            return host.Length <= 63 && DnsLabel.IsMatch(host);
        }

        foreach (var label in host.Split('.'))
        {
            if (label.Length == 0 || label.Length > 63 || !DnsLabel.IsMatch(label))
            {
                return false;
            }
        }

        return true;
    }

    public static bool IsSafePath(string? path) => path is null || PathRegex.IsMatch(path);

    public static bool IsValidShortId(string? sid) => string.IsNullOrEmpty(sid) || ShortIdRegex.IsMatch(sid);

    public static bool IsValidRealityKey(string? key) =>
        !string.IsNullOrEmpty(key) && RealityKeyRegex.IsMatch(key);

    public static bool IsUsableLocalPort(int port) => port is >= 1024 and <= 65535;
}
