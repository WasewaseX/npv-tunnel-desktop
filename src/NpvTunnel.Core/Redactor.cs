using System.Text.RegularExpressions;

namespace NpvTunnel.Core.Security;

/// <summary>
/// Scrubs credentials out of anything that leaves the process (log files, the
/// log view, crash reports, support bundles). NPV Tunnel's own logs print full
/// share links; that is one of the defects this port fixes.
/// </summary>
public static class Redactor
{
    private const string Mask = "«redacted»";

    private static readonly Regex UuidRegex = new(
        @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        RegexOptions.Compiled);

    private static readonly Regex ShareLinkRegex = new(
        @"(?i)\b(vless|vmess|trojan|ss|socks5?|hysteria2?|hy2|wireguard)://[^\s""']+",
        RegexOptions.Compiled);

    private static readonly Regex KeyValueSecretRegex = new(
        @"(?i)\b(password|passwd|pass|pwd|uuid|id|token|secret|pbk|publicKey|privateKey|method|auth)\b\s*[:=]\s*(""[^""]*""|'[^']*'|[^\s,;]+)",
        RegexOptions.Compiled);

    private static readonly Regex AuthHeaderRegex = new(
        @"(?i)(authorization|proxy-authorization)\s*:\s*(?:bearer\s+|basic\s+)?[^\s""']+",
        RegexOptions.Compiled);

    // A bare token with no header in front of it - copied out of a request dump,
    // or pasted into a log line by a caller that never saw the header name.
    private static readonly Regex BearerTokenRegex = new(
        @"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{6,}",
        RegexOptions.Compiled);

    public static string Scrub(string? input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        var s = ShareLinkRegex.Replace(input, m => $"{m.Groups[1].Value}://{Mask}");
        s = KeyValueSecretRegex.Replace(s, m => $"{m.Groups[1].Value}: {Mask}");
        s = AuthHeaderRegex.Replace(s, m => $"{m.Groups[1].Value}: {Mask}");
        s = BearerTokenRegex.Replace(s, $"Bearer {Mask}");
        s = UuidRegex.Replace(s, Mask);
        return s;
    }
}
