using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using NpvTunnel.Core.Models;
using NpvTunnel.Core.Security;
using NpvTunnel.Core.Util;

namespace NpvTunnel.Core.Import;

public static class UriParser
{
	public static readonly string[] Schemes = new string[10] { "vless", "vmess", "trojan", "ss", "socks", "socks5", "http", "https", "hysteria2", "hy2" };

	public static bool LooksLikeUri(string text)
	{
		string text2 = text.TrimStart();
		int num = text2.IndexOf("://", StringComparison.Ordinal);
		if (num <= 0)
		{
			return false;
		}
		string value = text2.Substring(0, num).ToLowerInvariant();
		return Schemes.Contains(value);
	}

	public static ImportResult Parse(string text)
	{
		if (string.IsNullOrWhiteSpace(text))
		{
			return ImportResult.Fail(ImportError.Empty, "The configuration is empty.");
		}
		string text2 = text.Trim();
		int num = text2.IndexOf("://", StringComparison.Ordinal);
		if (num <= 0)
		{
			return ImportResult.Fail(ImportError.UnknownFormat, "Not a recognised share link.");
		}
		string text3 = text2.Substring(0, num).ToLowerInvariant();
		string text4 = text2;
		int num2 = num + 3;
		string body = text4.Substring(num2, text4.Length - num2);
		try
		{
			ImportResult result;
			switch (text3)
			{
			case "vless":
				result = ParseVless(body);
				break;
			case "vmess":
				result = ParseVmess(body);
				break;
			case "trojan":
				result = ParseTrojan(body);
				break;
			case "ss":
				result = ParseShadowsocks(body);
				break;
			case "socks":
			case "socks5":
				result = ParseSocks(body);
				break;
			case "https":
			case "http":
				result = ParseHttp(body);
				break;
			case "hysteria2":
			case "hy2":
				result = ParseHysteria2(body);
				break;
			default:
				result = ImportResult.Fail(ImportError.UnknownFormat, "Scheme '" + text3 + "' is not supported.");
				break;
			}
			return result;
		}
		catch (Exception ex) when (((ex is FormatException || ex is JsonException || ex is ArgumentException) ? 1 : 0) != 0)
		{
			return ImportResult.Fail(ImportError.MalformedUri, "Malformed " + text3 + " link: " + ex.Message);
		}
	}

	private static ImportResult ParseVless(string body)
	{
		var (text, text2, port, query, fragment) = Split(body, expectUserInfo: true);
		if (!Guid.TryParse(text.Trim(), out var _))
		{
			return ImportResult.Fail(ImportError.InvalidField, "VLESS id is not a valid UUID.");
		}
		Profile obj = new Profile
		{
			Name = NameOrFallback(fragment, text2),
			Protocol = ProfileProtocol.Vless,
			Uuid = text.Trim(),
			Address = text2,
			Port = port
		};
		List<string> list = ApplyCommon(obj, query);
		obj.Flow = Q(query, "flow");
		string text3 = Q(query, "encryption");
		if (!string.IsNullOrEmpty(text3) && !text3.Equals("none", StringComparison.OrdinalIgnoreCase))
		{
			list.Add("VLESS encryption '" + text3 + "' is not supported (only 'none' is defined by the protocol).");
		}
		return Validate(obj, list);
	}

	private static ImportResult ParseVmess(string body)
	{
		if (!Base64Url.TryDecodeUtf8(body.Split('#')[0], out string decoded))
		{
			return ImportResult.Fail(ImportError.MalformedUri, "VMess payload is not valid base64.");
		}
		using JsonDocument jsonDocument = SafeJson.Parse(decoded);
		JsonElement rootElement = jsonDocument.RootElement;
		if (rootElement.ValueKind != JsonValueKind.Object)
		{
			return ImportResult.Fail(ImportError.MalformedUri, "VMess payload is not a JSON object.");
		}
		string text = Str(rootElement, "id");
		if (!Guid.TryParse(text, out var _))
		{
			return ImportResult.Fail(ImportError.InvalidField, "VMess id is not a valid UUID.");
		}
		Profile profile = new Profile();
		string text2 = Str(rootElement, "ps");
		profile.Name = ((text2 != null && text2.Length > 0) ? text2 : Str(rootElement, "add"));
		profile.Protocol = ProfileProtocol.Vmess;
		profile.Uuid = text;
		profile.Address = Str(rootElement, "add");
		profile.Port = Int(rootElement, "port", 443);
		profile.AlterId = Int(rootElement, "aid", 0);
		string text3 = Str(rootElement, "scy");
		profile.VmessSecurity = ((text3 != null && text3.Length > 0) ? text3 : "auto");
		profile.Sni = Str(rootElement, "sni");
		profile.Fingerprint = Str(rootElement, "fp");
		string text4 = Str(rootElement, "path");
		profile.Path = ((text4 != null && text4.Length > 0) ? text4 : "/");
		profile.Host = Str(rootElement, "host");
		string text5 = Str(rootElement, "path");
		profile.ServiceName = ((text5 != null && text5.Length > 0) ? text5 : string.Empty);
		string text6 = Str(rootElement, "net");
		profile.Transport = MapTransport((text6 != null && text6.Length > 0) ? text6 : "tcp");
		Profile profile2 = profile;
		if (Str(rootElement, "tls").Equals("tls", StringComparison.OrdinalIgnoreCase))
		{
			profile2.Security = SecurityLayer.Tls;
		}
		profile2.Alpn = SplitList(Str(rootElement, "alpn"));
		profile2.AllowInsecure = Int(rootElement, "allowInsecure", 0) == 1 || Str(rootElement, "allowInsecure") == "true";
		List<string> list = new List<string>();
		if (profile2.AlterId > 0)
		{
			list.Add("alterId > 0 is a legacy AEAD setting; the server must support VMess AEAD.");
		}
		if (profile2.AllowInsecure)
		{
			profile2.AllowInsecure = false;
			list.Add("Certificate verification bypass requested by the link was ignored. Enable it explicitly in Settings if you trust this server.");
		}
		return Validate(profile2, list);
	}

	private static ImportResult ParseTrojan(string body)
	{
		(string userInfo, string host, int port, Dictionary<string, string> query, string fragment) tuple = Split(body, expectUserInfo: true);
		string item = tuple.userInfo;
		string item2 = tuple.host;
		int item3 = tuple.port;
		Dictionary<string, string> item4 = tuple.query;
		string item5 = tuple.fragment;
		Profile profile = new Profile
		{
			Name = NameOrFallback(item5, item2),
			Protocol = ProfileProtocol.Trojan,
			Password = Uri.UnescapeDataString(item),
			Address = item2,
			Port = item3,
			Security = SecurityLayer.Tls
		};
		List<string> warnings = ApplyCommon(profile, item4);
		string text = Q(item4, "security");
		if (text.Equals("none", StringComparison.OrdinalIgnoreCase) || text.Equals("reality", StringComparison.OrdinalIgnoreCase))
		{
			profile.Security = (text.Equals("reality", StringComparison.OrdinalIgnoreCase) ? SecurityLayer.Reality : SecurityLayer.None);
		}
		return Validate(profile, warnings);
	}

	private static ImportResult ParseShadowsocks(string body)
	{
		string text = string.Empty;
		int num = body.IndexOf('#');
		if (num >= 0)
		{
			string text2 = body;
			int num2 = num + 1;
			text = Uri.UnescapeDataString(text2.Substring(num2, text2.Length - num2));
			body = body.Substring(0, num);
		}
		Dictionary<string, string> dictionary = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		int num3 = body.IndexOf('?');
		if (num3 >= 0)
		{
			string text3 = body;
			int num4 = num3 + 1;
			dictionary = ParseQuery(text3.Substring(num4, text3.Length - num4));
			body = body.Substring(0, num3);
		}
		int num5 = body.LastIndexOf('@');
		string text6;
		int port;
		string text7;
		string password;
		if (num5 >= 0)
		{
			string text4 = body.Substring(0, num5);
			string text5 = body;
			int num6 = num5 + 1;
			(text6, port) = SplitHostPort(text5.Substring(num6, text5.Length - num6));
			if (text4.Contains(':'))
			{
				int num7 = text4.IndexOf(':');
				text7 = Uri.UnescapeDataString(text4.Substring(0, num7));
				text5 = text4;
				num6 = num7 + 1;
				password = Uri.UnescapeDataString(text5.Substring(num6, text5.Length - num6));
			}
			else
			{
				if (!Base64Url.TryDecodeUtf8(text4, out string decoded) || !decoded.Contains(':'))
				{
					return ImportResult.Fail(ImportError.MalformedUri, "Shadowsocks credentials are not readable.");
				}
				int num8 = decoded.IndexOf(':');
				text7 = decoded.Substring(0, num8);
				text5 = decoded;
				num6 = num8 + 1;
				password = text5.Substring(num6, text5.Length - num6);
			}
		}
		else
		{
			if (!Base64Url.TryDecodeUtf8(body, out string decoded2))
			{
				return ImportResult.Fail(ImportError.MalformedUri, "Shadowsocks payload is not valid base64.");
			}
			int num9 = decoded2.LastIndexOf('@');
			if (num9 < 0)
			{
				return ImportResult.Fail(ImportError.MalformedUri, "Shadowsocks payload has no host.");
			}
			string text8 = decoded2.Substring(0, num9);
			int num10 = text8.IndexOf(':');
			if (num10 < 0)
			{
				return ImportResult.Fail(ImportError.MalformedUri, "Shadowsocks payload has no cipher.");
			}
			text7 = text8.Substring(0, num10);
			string text9 = text8;
			int num11 = num10 + 1;
			password = text9.Substring(num11, text9.Length - num11);
			text9 = decoded2;
			num11 = num9 + 1;
			(text6, port) = SplitHostPort(text9.Substring(num11, text9.Length - num11));
		}
		Profile profile = new Profile
		{
			Name = ((text.Length > 0) ? text : text6),
			Protocol = ProfileProtocol.Shadowsocks,
			Method = text7,
			Password = password,
			Address = text6,
			Port = port
		};
		List<string> list = new List<string>();
		if (!IsSupportedCipher(text7))
		{
			list.Add("Cipher '" + text7 + "' is not in the supported list; the engine may refuse to start.");
		}
		if (dictionary.ContainsKey("plugin"))
		{
			list.Add("Shadowsocks plugins (obfs / v2ray-plugin) are not supported by the desktop engine yet.");
		}
		return Validate(profile, list);
	}

	private static bool IsSupportedCipher(string method)
	{
		switch (method.ToLowerInvariant())
		{
		case "aes-128-gcm":
		case "aes-256-gcm":
		case "2022-blake3-aes-128-gcm":
		case "2022-blake3-aes-256-gcm":
		case "xchacha20-ietf-poly1305":
		case "chacha20-poly1305":
		case "chacha20-ietf-poly1305":
		case "xchacha20-poly1305":
		case "2022-blake3-chacha20-poly1305":
		case "none":
		case "plain":
			return true;
		default:
			return false;
		}
	}

	private static ImportResult ParseSocks(string body)
	{
		var (userInfo, host, port, _, fragment) = Split(body, expectUserInfo: false, allowNoUserInfo: true);
		return BuildLocalProxy(ProfileProtocol.Socks, userInfo, host, port, fragment);
	}

	private static ImportResult ParseHttp(string body)
	{
		var (userInfo, host, port, _, fragment) = Split(body, expectUserInfo: false, allowNoUserInfo: true);
		return BuildLocalProxy(ProfileProtocol.Http, userInfo, host, port, fragment);
	}

	private static ImportResult BuildLocalProxy(ProfileProtocol protocol, string userInfo, string host, int port, string fragment)
	{
		string username = string.Empty;
		string password = string.Empty;
		if (!string.IsNullOrEmpty(userInfo))
		{
			string text = userInfo;
			if (!text.Contains(':') && Base64Url.TryDecodeUtf8(userInfo, out string decoded) && decoded.Contains(':'))
			{
				text = decoded;
			}
			int num = text.IndexOf(':');
			if (num >= 0)
			{
				username = Uri.UnescapeDataString(text.Substring(0, num));
				string text2 = text;
				int num2 = num + 1;
				password = Uri.UnescapeDataString(text2.Substring(num2, text2.Length - num2));
			}
			else
			{
				username = Uri.UnescapeDataString(text);
			}
		}
		return Validate(new Profile
		{
			Name = NameOrFallback(fragment, host),
			Protocol = protocol,
			Address = host,
			Port = port,
			Username = username,
			Password = password,
			Security = SecurityLayer.None
		}, new List<string>());
	}

	private static ImportResult ParseHysteria2(string body)
	{
		(string userInfo, string host, int port, Dictionary<string, string> query, string fragment) tuple = Split(body, expectUserInfo: false, allowNoUserInfo: true);
		string item = tuple.userInfo;
		string item2 = tuple.host;
		int item3 = tuple.port;
		Dictionary<string, string> item4 = tuple.query;
		string item5 = tuple.fragment;
		Profile profile = new Profile
		{
			Name = NameOrFallback(item5, item2),
			Protocol = ProfileProtocol.Hysteria2,
			Password = Uri.UnescapeDataString(item),
			Address = item2,
			Port = item3,
			Security = SecurityLayer.Tls,
			Sni = Q(item4, "sni")
		};
		int num = 1;
		List<string> list = new List<string>(num);
		CollectionsMarshal.SetCount(list, num);
		Span<string> span = CollectionsMarshal.AsSpan(list);
		int num2 = 0;
		span[num2] = "Hysteria2 needs the sing-box engine, which is not bundled. The profile is stored but cannot connect yet.";
		num2++;
		return Validate(profile, list);
	}

	internal static ImportResult Validate(Profile profile, List<string> warnings)
	{
		if (string.IsNullOrWhiteSpace(profile.Address))
		{
			return ImportResult.Fail(ImportError.InvalidField, "The server address is empty.");
		}
		int port = profile.Port;
		if (port < 1 || port > 65535)
		{
			return ImportResult.Fail(ImportError.InvalidField, $"Port {profile.Port} is out of range.");
		}
		if (!Validators.IsSafeHost(profile.Address))
		{
			return ImportResult.Fail(ImportError.InvalidField, "The server address contains characters that are not allowed.");
		}
		if (profile.Name.Length > 120)
		{
			profile.Name = profile.Name.Substring(0, 120);
		}
		switch (profile.Protocol)
		{
		case ProfileProtocol.Vless:
		case ProfileProtocol.Vmess:
			if (string.IsNullOrWhiteSpace(profile.Uuid))
			{
				return ImportResult.Fail(ImportError.MissingCredential, "The configuration has no UUID.");
			}
			break;
		case ProfileProtocol.Trojan:
		case ProfileProtocol.Shadowsocks:
			if (string.IsNullOrWhiteSpace(profile.Password))
			{
				return ImportResult.Fail(ImportError.MissingCredential, "The configuration has no password.");
			}
			break;
		}
		return ImportResult.Ok(profile, warnings.ToArray());
	}

	private static List<string> ApplyCommon(Profile profile, Dictionary<string, string> query)
	{
		List<string> list = new List<string>();
		string text = Q(query, "type");
		if (text.Length > 0)
		{
			profile.Transport = MapTransport(text, list);
		}
		string text2 = Q(query, "security");
		string text3;
		if (text2.Length > 0)
		{
			text3 = text2.ToLowerInvariant();
			SecurityLayer security;
			switch (text3)
			{
			default:
				if (text3.Length == 0)
				{
					goto case "none";
				}
				goto case null;
			case "tls":
				security = SecurityLayer.Tls;
				break;
			case "reality":
				security = SecurityLayer.Reality;
				break;
			case "none":
				security = SecurityLayer.None;
				break;
			case null:
				security = profile.Security;
				break;
			}
			profile.Security = security;
		}
		string text4 = Q(query, "sni");
		profile.Sni = ((text4 != null && text4.Length > 0) ? text4 : Q(query, "peer"));
		profile.Fingerprint = Q(query, "fp");
		profile.PublicKey = Q(query, "pbk");
		profile.ShortId = Q(query, "sid");
		profile.SpiderX = Q(query, "spx");
		string text5 = Q(query, "path");
		profile.Path = ((text5 != null && text5.Length > 0) ? Uri.UnescapeDataString(text5) : profile.Path);
		profile.Host = Q(query, "host");
		profile.ServiceName = Q(query, "serviceName");
		profile.Alpn = SplitList(Q(query, "alpn"));
		string text6 = Q(query, "allowInsecure") + Q(query, "insecure") + Q(query, "allowinsecure");
		text3 = text6.Trim('0');
		if (text3 != null && text3.Length > 0 && !text6.Equals("false", StringComparison.OrdinalIgnoreCase))
		{
			profile.AllowInsecure = false;
			list.Add("Certificate verification bypass requested by the link was ignored. Enable it explicitly in Settings if you trust this server.");
		}
		if (profile.Security == SecurityLayer.Reality)
		{
			if (profile.PublicKey.Length == 0)
			{
				list.Add("REALITY link has no pbk (public key); the connection will fail.");
			}
			if (profile.Sni.Length == 0)
			{
				list.Add("REALITY link has no SNI; the connection will fail.");
			}
		}
		if (profile.Transport == Transport.Tcp && profile.Flow.Length == 0 && Q(query, "headerType") == "http")
		{
			list.Add("TCP header obfuscation (headerType=http) is not supported by the desktop engine.");
		}
		return list;
	}

	private static Transport MapTransport(string value, List<string>? warnings = null)
	{
		switch (value.ToLowerInvariant())
		{
		case "raw":
		case "tcp":
		case "":
			return Transport.Tcp;
		case "websocket":
		case "ws":
			return Transport.WebSocket;
		case "gun":
		case "grpc":
			return Transport.Grpc;
		case "httpupgrade":
			return Transport.HttpUpgrade;
		case "splithttp":
		case "xhttp":
			return Transport.Xhttp;
		case "quic":
			return Transport.Quic;
		default:
			return UnknownTransport(value, warnings);
		}
	}

	private static Transport UnknownTransport(string value, List<string>? warnings)
	{
		warnings?.Add("Transport '" + value + "' is not supported; falling back to raw TCP.");
		return Transport.Tcp;
	}

	private static (string userInfo, string host, int port, Dictionary<string, string> query, string fragment) Split(string body, bool expectUserInfo, bool allowNoUserInfo = false)
	{
		string item = string.Empty;
		int num = body.IndexOf('#');
		if (num >= 0)
		{
			string text = body;
			int num2 = num + 1;
			item = Uri.UnescapeDataString(text.Substring(num2, text.Length - num2));
			body = body.Substring(0, num);
		}
		Dictionary<string, string> item2 = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		int num3 = body.IndexOf('?');
		if (num3 >= 0)
		{
			string text2 = body;
			int num4 = num3 + 1;
			item2 = ParseQuery(text2.Substring(num4, text2.Length - num4));
			body = body.Substring(0, num3);
		}
		body = body.TrimEnd('/');
		string item3 = string.Empty;
		int num5 = body.LastIndexOf('@');
		string value;
		if (num5 < 0)
		{
			value = ((!expectUserInfo || allowNoUserInfo) ? body : body);
		}
		else
		{
			item3 = body.Substring(0, num5);
			string text3 = body;
			int num6 = num5 + 1;
			value = text3.Substring(num6, text3.Length - num6);
		}
		var (item4, item5) = SplitHostPort(value);
		return (userInfo: item3, host: item4, port: item5, query: item2, fragment: item);
	}

	private static (string host, int port) SplitHostPort(string value)
	{
		value = value.Trim();
		string text;
		int num2;
		if (value.StartsWith('['))
		{
			int num = value.IndexOf(']');
			if (num < 0)
			{
				throw new FormatException("Unterminated IPv6 literal.");
			}
			string item = value.Substring(1, num - 1);
			text = value;
			num2 = num + 1;
			string text2 = text.Substring(num2, text.Length - num2).TrimStart(':');
			int item2 = ((text2.Length == 0) ? 443 : ParsePort(text2));
			return (host: item, port: item2);
		}
		int num3 = value.LastIndexOf(':');
		if (num3 < 0)
		{
			return (host: value, port: 443);
		}
		string item3 = value.Substring(0, num3);
		text = value;
		num2 = num3 + 1;
		string text3 = text.Substring(num2, text.Length - num2);
		return (host: item3, port: (text3.Length == 0) ? 443 : ParsePort(text3));
	}

	private static int ParsePort(string value)
	{
		int result;
		bool flag = !int.TryParse(value, out result);
		if (!flag)
		{
			flag = ((result < 1 || result > 65535) ? true : false);
		}
		if (flag)
		{
			throw new FormatException("'" + value + "' is not a valid port.");
		}
		return result;
	}

	private static Dictionary<string, string> ParseQuery(string query)
	{
		Dictionary<string, string> dictionary = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		string[] array = query.Split('&', StringSplitOptions.RemoveEmptyEntries);
		foreach (string text in array)
		{
			int num = text.IndexOf('=');
			if (num < 0)
			{
				dictionary[Uri.UnescapeDataString(text)] = string.Empty;
				continue;
			}
			string key = Uri.UnescapeDataString(text.Substring(0, num));
			string text2 = text;
			int num2 = num + 1;
			string value = Uri.UnescapeDataString(text2.Substring(num2, text2.Length - num2));
			dictionary[key] = value;
		}
		return dictionary;
	}

	private static string Q(Dictionary<string, string> query, string key)
	{
		if (!query.TryGetValue(key, out string value))
		{
			return string.Empty;
		}
		return value;
	}

	private static string NameOrFallback(string fragment, string host)
	{
		if (!string.IsNullOrWhiteSpace(fragment))
		{
			return fragment.Trim();
		}
		if (!string.IsNullOrWhiteSpace(host))
		{
			return host;
		}
		return "Untitled";
	}

	private static IReadOnlyList<string> SplitList(string value)
	{
		if (!string.IsNullOrWhiteSpace(value))
		{
			return value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
		}
		return Array.Empty<string>();
	}

	private static string Str(JsonElement root, string name)
	{
		if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
		{
			if (value.ValueKind != JsonValueKind.Number)
			{
				return string.Empty;
			}
			return value.ToString();
		}
		return value.GetString() ?? string.Empty;
	}

	private static int Int(JsonElement root, string name, int fallback)
	{
		if (!root.TryGetProperty(name, out var value))
		{
			return fallback;
		}
		switch (value.ValueKind)
		{
		case JsonValueKind.Number:
		{
			if (value.TryGetInt32(out var value2))
			{
				return value2;
			}
			break;
		}
		case JsonValueKind.String:
		{
			if (int.TryParse(value.GetString(), out var result))
			{
				return result;
			}
			break;
		}
		}
		return fallback;
	}

	internal static string Describe(Profile p)
	{
		return new StringBuilder().Append(p.Protocol).Append(" ").Append(p.Endpoint)
			.ToString();
	}
}
