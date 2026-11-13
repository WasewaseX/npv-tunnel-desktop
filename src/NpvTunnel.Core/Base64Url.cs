using System;
using System.Text;

namespace NpvTunnel.Core.Util;

public static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> data)
    {
        return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-')
            .Replace('/', '_');
    }

    public static byte[] Decode(string input)
    {
        ArgumentNullException.ThrowIfNull(input, "input");
        string text = input.Trim().Replace('-', '+').Replace('_', '/');
        switch (text.Length % 4)
        {
            case 2:
                text += "==";
                break;
            case 3:
                text += "=";
                break;
            case 1:
                throw new FormatException("Invalid base64 length.");
        }
        return Convert.FromBase64String(text);
    }

    public static bool TryDecodeUtf8(string input, out string decoded)
    {
        decoded = string.Empty;
        try
        {
            decoded = Encoding.UTF8.GetString(Decode(input));
            return true;
        }
        catch (Exception ex) when (((ex is FormatException || ex is ArgumentException) ? 1 : 0) != 0)
        {
            return false;
        }
    }
}
