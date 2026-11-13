using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace NpvTunnel.App.Services;

public static class SecretStore
{
    private const int CurrentVersion = 1;

    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("NpvTunnel.Desktop.Profiles.v1");

    private static readonly byte[] Magic = "NPVTD1"u8.ToArray();

    public static void SaveEncrypted(string path, string plaintext)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] array;
        try
        {
            array = ProtectedData.Protect(bytes, Entropy, (DataProtectionScope)0);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
        string? directoryName = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directoryName))
        {
            Directory.CreateDirectory(directoryName);
        }
        string text = path + ".tmp";
        using (FileStream fileStream = new FileStream(text, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            fileStream.Write(Magic);
            fileStream.WriteByte(1);
            fileStream.Write(array);
            fileStream.Flush(flushToDisk: true);
        }
        File.Move(text, path, overwrite: true);
    }

    public static string? LoadEncrypted(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }
        try
        {
            byte[] array = File.ReadAllBytes(path);
            if (array.Length < Magic.Length + 1 || !array.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            {
                return null;
            }
            if (array[Magic.Length] != 1)
            {
                return null;
            }
            byte[] array2 = ProtectedData.Unprotect(array.AsSpan(Magic.Length + 1).ToArray(), Entropy, (DataProtectionScope)0);
            try
            {
                return Encoding.UTF8.GetString(array2);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(array2);
            }
        }
        catch (Exception ex) when (((ex is CryptographicException || ex is IOException || ex is UnauthorizedAccessException) ? 1 : 0) != 0)
        {
            return null;
        }
    }

    public static void SecureDelete(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return;
            }
            long length = new FileInfo(path).Length;
            using (FileStream fileStream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
            {
                byte[] array = new byte[Math.Min(length, 81920L)];
                long num = length;
                while (num > 0)
                {
                    int num2 = (int)Math.Min(array.Length, num);
                    RandomNumberGenerator.Fill(array.AsSpan(0, num2));
                    fileStream.Write(array, 0, num2);
                    num -= num2;
                }
                fileStream.Flush(flushToDisk: true);
            }
            File.Delete(path);
        }
        catch (Exception ex) when (((ex is IOException || ex is UnauthorizedAccessException) ? 1 : 0) != 0)
        {
        }
    }
}
