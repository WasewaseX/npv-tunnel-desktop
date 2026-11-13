using System;
using System.Security.Cryptography;
using System.Text;
using NpvTunnel.Core.Util;

namespace NpvTunnel.Core.Security;

public static class LockedConfig
{
	public const string Magic = "NPVT-LOCK1";

	private const int SaltSize = 16;

	private const int NonceSize = 12;

	private const int TagSize = 16;

	private const int KeySize = 32;

	private const int Iterations = 210000;

	public static bool IsEnvelope(string text)
	{
		if (string.IsNullOrWhiteSpace(text))
		{
			return false;
		}
		string text2 = text.Trim();
		if (text2.Length < 40 || text2.Length > 2000000)
		{
			return false;
		}
		try
		{
			byte[] array = Base64Url.Decode(text2);
			return array.Length > "NPVT-LOCK1".Length + 16 + 12 + 16 && Encoding.ASCII.GetString(array, 0, "NPVT-LOCK1".Length) == "NPVT-LOCK1";
		}
		catch (FormatException)
		{
			return false;
		}
	}

	public static string Lock(string plaintext, string passphrase)
	{
		ArgumentException.ThrowIfNullOrEmpty(passphrase, "passphrase");
		if (passphrase.Length < 8)
		{
			throw new ArgumentException("Passphrase must be at least 8 characters.", "passphrase");
		}
		byte[] bytes = RandomNumberGenerator.GetBytes(16);
		byte[] bytes2 = RandomNumberGenerator.GetBytes(12);
		byte[] array = DeriveKey(passphrase, bytes);
		byte[] bytes3 = Encoding.UTF8.GetBytes(plaintext);
		byte[] array2 = new byte[bytes3.Length];
		byte[] array3 = new byte[16];
		try
		{
			using AesGcm aesGcm = new AesGcm(array, 16);
			aesGcm.Encrypt(bytes2, bytes3, array2, array3);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(array);
			CryptographicOperations.ZeroMemory(bytes3);
		}
		byte[] bytes4 = Encoding.ASCII.GetBytes("NPVT-LOCK1");
		byte[] array4 = new byte[bytes4.Length + 16 + 12 + 16 + array2.Length];
		int num = 0;
		Buffer.BlockCopy(bytes4, 0, array4, num, bytes4.Length);
		num += bytes4.Length;
		Buffer.BlockCopy(bytes, 0, array4, num, 16);
		num += 16;
		Buffer.BlockCopy(bytes2, 0, array4, num, 12);
		num += 12;
		Buffer.BlockCopy(array3, 0, array4, num, 16);
		num += 16;
		Buffer.BlockCopy(array2, 0, array4, num, array2.Length);
		return Base64Url.Encode(array4);
	}

	public static string? TryUnlock(string envelope, string passphrase)
	{
		byte[] array;
		try
		{
			array = Base64Url.Decode(envelope.Trim());
		}
		catch (FormatException)
		{
			return null;
		}
		byte[] bytes = Encoding.ASCII.GetBytes("NPVT-LOCK1");
		if (array.Length <= bytes.Length + 16 + 12 + 16)
		{
			return null;
		}
		if (!array.AsSpan(0, bytes.Length).SequenceEqual(bytes))
		{
			return null;
		}
		int num = bytes.Length;
		Span<byte> span = array.AsSpan(num, 16);
		num += 16;
		Span<byte> span2 = array.AsSpan(num, 12);
		num += 12;
		Span<byte> span3 = array.AsSpan(num, 16);
		num += 16;
		Span<byte> span4 = array.AsSpan(num);
		byte[] array2 = DeriveKey(passphrase, span);
		byte[] array3 = new byte[span4.Length];
		try
		{
			using AesGcm aesGcm = new AesGcm(array2, 16);
			aesGcm.Decrypt(span2, span4, span3, array3);
			return Encoding.UTF8.GetString(array3);
		}
		catch (CryptographicException)
		{
			return null;
		}
		finally
		{
			CryptographicOperations.ZeroMemory(array2);
			CryptographicOperations.ZeroMemory(array3);
		}
	}

	private static byte[] DeriveKey(string passphrase, ReadOnlySpan<byte> salt)
	{
		return Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(passphrase), salt.ToArray(), 210000, HashAlgorithmName.SHA256, 32);
	}
}
