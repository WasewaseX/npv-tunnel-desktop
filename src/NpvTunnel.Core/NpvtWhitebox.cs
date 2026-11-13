using System;
using System.Buffers.Binary;

namespace NpvTunnel.Core.Import;

/// <summary>
/// The white-box cipher NPV Tunnel uses for its .npvt containers.
/// </summary>
/// <remarks>
/// A two-round substitution-permutation network used as the keystream of a CTR
/// construction: the AES S-box and the AES ShiftRows order, a bespoke per-column
/// 32x32 GF(2) mixing layer, three fixed round keys, and a generation table in the
/// final round. There is no user key - the cipher is the obfuscation, which is
/// exactly why a desktop client can read the files channels distribute.
///
/// Ported from the MIT-licensed Go reference implementation in
/// github.com/masihyeganeh/npvs, which derives the tables from
/// github.com/FrontierTM/Pantegnos. See THIRD-PARTY-NOTICES.md.
///
/// Known-answer test: Core(00 01 02 .. 0f) == 58 bf 2e cb d0 52 f9 cd b4 70 4a c2 b7 fd a3 75.
/// </remarks>
public static class NpvtWhitebox
{
    private static readonly byte[] Sbox =
    {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    };

    // AES ShiftRows byte permutation.
    private static readonly int[] ShiftOrder = { 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11 };

    private static readonly byte[] K0 = { 0xd4, 0x6b, 0x21, 0x8c, 0xbe, 0x34, 0xc8, 0xaa, 0xaa, 0xfa, 0x5d, 0x4a, 0xc1, 0xf4, 0x5a, 0xb7 };
    private static readonly byte[] K1 = { 0xaa, 0xb9, 0xf0, 0x43, 0x14, 0xdc, 0x38, 0xe9, 0xbe, 0x26, 0x8b, 0xa3, 0x7f, 0xd2, 0xd1, 0xcf };
    private static readonly byte[] K2 = { 0xfe, 0xdb, 0x81, 0x1d, 0xea, 0xfd, 0x50, 0x5e, 0x54, 0x2f, 0xa0, 0xb7, 0x2b, 0x96, 0x98, 0x14 };

    // Bespoke linear mixing layer: Mix[c] holds the 32 images of the input bits
    // for column c (input byte 0 is the most significant byte).
    private static readonly uint[][] Mix =
    {
        new uint[]
        {
            0xc1a35b69u, 0xe834e3b4u, 0x72aed1f9u, 0xcc13c6f3u, 0x10a20702u, 0x05a47f66u, 0xff70858au, 0xca26e3c5u,
            0xc1a35b69u, 0xe834e3b4u, 0x72aed1f9u, 0xcc13c6f3u, 0x10a20702u, 0x05a47f66u, 0xff70858au, 0xca26e3c5u,
            0xc1a35b69u, 0xe834e3b4u, 0x72aed1f9u, 0xcc13c6f3u, 0x10a20702u, 0x05a47f66u, 0xff70858au, 0xca26e3c5u,
            0xc1a35b69u, 0xe834e3b4u, 0x72aed1f9u, 0xcc13c6f3u, 0x10a20702u, 0x05a47f66u, 0xff70858au, 0xca26e3c5u,
        },
        new uint[]
        {
            0xc071d765u, 0x7c6e59f2u, 0x625cc067u, 0x17047376u, 0x6f28c144u, 0xba06ead6u, 0x7b55a790u, 0x1559a81au,
            0xc071d765u, 0x7c6e59f2u, 0x625cc067u, 0x17047376u, 0x6f28c144u, 0xba06ead6u, 0x7b55a790u, 0x1559a81au,
            0xc071d765u, 0x7c6e59f2u, 0x625cc067u, 0x17047376u, 0x6f28c144u, 0xba06ead6u, 0x7b55a790u, 0x1559a81au,
            0xc071d765u, 0x7c6e59f2u, 0x625cc067u, 0x17047376u, 0x6f28c144u, 0xba06ead6u, 0x7b55a790u, 0x1559a81au,
        },
        new uint[]
        {
            0x7088767au, 0x315b8f10u, 0xba4f3425u, 0x1e3d907bu, 0x66b163c9u, 0x53890febu, 0x3b347002u, 0x8195b5e4u,
            0x7088767au, 0x315b8f10u, 0xba4f3425u, 0x1e3d907bu, 0x66b163c9u, 0x53890febu, 0x3b347002u, 0x8195b5e4u,
            0x7088767au, 0x315b8f10u, 0xba4f3425u, 0x1e3d907bu, 0x66b163c9u, 0x53890febu, 0x3b347002u, 0x8195b5e4u,
            0x7088767au, 0x315b8f10u, 0xba4f3425u, 0x1e3d907bu, 0x66b163c9u, 0x53890febu, 0x3b347002u, 0x8195b5e4u,
        },
        new uint[]
        {
            0x92a16564u, 0x0860463bu, 0x854c4204u, 0x817172c1u, 0x14eff0a2u, 0xed237113u, 0x17836853u, 0x0f6a2a64u,
            0x92a16564u, 0x0860463bu, 0x854c4204u, 0x817172c1u, 0x14eff0a2u, 0xed237113u, 0x17836853u, 0x0f6a2a64u,
            0x92a16564u, 0x0860463bu, 0x854c4204u, 0x817172c1u, 0x14eff0a2u, 0xed237113u, 0x17836853u, 0x0f6a2a64u,
            0x92a16564u, 0x0860463bu, 0x854c4204u, 0x817172c1u, 0x14eff0a2u, 0xed237113u, 0x17836853u, 0x0f6a2a64u,
        },
    };

    // Final-round lookup: 16 x 256 bytes, generation 2.
    private static readonly byte[] FinalTable = DecodeFinalTable();

    /// <summary>One 16-byte block transform: counter in, keystream out.</summary>
    public static void Core(ReadOnlySpan<byte> block, Span<byte> output)
    {
        Span<byte> st = stackalloc byte[16];
        for (int i = 0; i < 16; i++)
        {
            st[i] = (byte)(block[i] ^ K0[i]);
        }

        Shift(st);
        for (int i = 0; i < 16; i++)
        {
            st[i] = Sbox[st[i]];
        }

        Span<byte> column = stackalloc byte[4];
        for (int c = 0; c < 4; c++)
        {
            MixColumn(st.Slice(c * 4, 4), Mix[c], column);
            column.CopyTo(st.Slice(c * 4, 4));
        }

        Shift(st);
        for (int i = 0; i < 16; i++)
        {
            output[i] = FinalTable[(i * 256) + st[i]];
        }
    }

    /// <summary>Applies the keystream: the first 16 bytes are the nonce, the rest is data.</summary>
    public static byte[] Decrypt(byte[] payload)
    {
        if (payload.Length <= 16)
        {
            return Array.Empty<byte>();
        }

        int length = payload.Length - 16;
        var output = new byte[length];
        Span<byte> counter = stackalloc byte[16];
        Span<byte> keystream = stackalloc byte[16];
        payload.AsSpan(0, 16).CopyTo(counter);

        for (int offset = 0; offset < length; offset += 16)
        {
            Core(counter, keystream);
            Increment(counter);

            int count = Math.Min(length - offset, 16);
            for (int i = 0; i < count; i++)
            {
                output[offset + i] = (byte)(payload[16 + offset + i] ^ keystream[i]);
            }
        }

        return output;
    }

    private static void Increment(Span<byte> counter)
    {
        // Big-endian increment, matching the reference implementation.
        for (int i = 15; i >= 0; i--)
        {
            counter[i]++;
            if (counter[i] != 0)
            {
                return;
            }
        }
    }

    private static void Shift(Span<byte> state)
    {
        Span<byte> copy = stackalloc byte[16];
        state.CopyTo(copy);
        for (int i = 0; i < 16; i++)
        {
            state[i] = copy[ShiftOrder[i]];
        }
    }

    private static void MixColumn(ReadOnlySpan<byte> column, uint[] image, Span<byte> output)
    {
        uint x = ((uint)column[0] << 24) | ((uint)column[1] << 16) | ((uint)column[2] << 8) | column[3];
        uint w = 0;
        for (int bit = 0; bit < 32; bit++)
        {
            if (((x >> (31 - bit)) & 1u) == 1u)
            {
                w ^= image[bit];
            }
        }

        BinaryPrimitives.WriteUInt32BigEndian(output, w);
    }

    private static byte[] DecodeFinalTable()
    {
        const string table =
            "Upw8LRqHb2vE9B7M2qK3+AoUkqhQ9puEyZMZNrBXcyuAwzpZ542ao+0SM/K66aFpRuq4EPUlIKCxIp5/bnbc1HkXZeDWITCr" +
            "Zu8fBnBqlyfT8b9nRehOqnfzcl+8lkEYiuEWI3V0tUPb0ESGSjjiWKlHn8vjYHg/S5iOwAjwtv0bD8pbz+uPJm3YSQMJMsjB" +
            "fhz57EyLFdndPfo5+2TmaJnVzv9ViAApiYWdgpE7DJVcUVMqjD5iWjeDNHy5DgSn/IG7B2FWrsJUBS4RzXu9syTfQkgNLO4B" +
            "vnGvXcYLbGMoTazF0XrXHdLk932kXuWQQMeUNaYxtLL+E60vT6XeAl0axkW67oxik9gt1avlbr2QZlBRMwavxMd9bx1ho/71" +
            "a49gzZpC9tRkPZmzV3pS1hWO8wRAxVwysgJVTzojQ8oFhdAAnTVjz/nxS1O7WpQHv4bCqB98peaETJ/MFtfIN76hddO3jS8x" +
            "Vg6VcjwT7LZKTj+iGQh3uZLd/4c76eHRkZeDFLEQZeL7J2qAiArbNvI49F+J4A1owLWBe9JY98HLJCgJZ20B+klG4y6KeJtU" +
            "i+dEc54i2aSYluheCzRxIEd/qRt2D3l0IYKcKxFZEqYlDHCt69q88CmwtB64p6ygMPxprtzJWznDTd5B3xz4GKoD6s7vfj4q" +
            "7eQsF2wmSP28/yZF8pjc5W2SjUyWxRbelTlvx1qK319dzgDhCRGro+MtUkP4ZRQQi7uzYd2lh8hrddftiS/75Oy2SWYoz1QM" +
            "nvVcaQsKPMqvpPk7RzUnnTjWtOAfnEAH5zS/8Y93gsloBp8aXqnUT5AZeWAVD1jojqwYwJc61TGMCCAN6cNnPqrmgLH3KlZ/" +
            "+vb94kTu6nMuI1UsQfMlHfxIA0txxth7cGQktZSwWfCnEnw2TXa+t2MBk4b0M6ZqQqJGhRuEF5kyV7rTBa5iqJutAogh2++a" +
            "uD9K607ZzctsgVDS2jB9of6DeMQpHr3ReituUQSyzMKgWzc9U3J+kQ7BItB0uRwTl5agVgJpwPXbqbsBMzhlp4MA3JukSih8" +
            "E+seVXuoI23CNUjT9JoDhomTxHQMheX8C6ZJrRIwhFx1X/uiEJS8kW4EQHkgY7rZClmKQvEOEdDGFkPDCaXzW5WNNz/BUpx9" +
            "ZPmIjH+xzt9BORtUFycv/RWzZ3j36UtxtFPIkHAq1fqZMv40rssmT71HcwYHMZ4U0kVRVySj1ndGrOE98B3MTrWCIU1iH+RY" +
            "mC5QXua38s3P7uINPMeroeglgI+SXb5Ma7bK4zZ6HC3YcnbvZmphft1vuYGyv8mw7VpE52DUn9cILMVs7Pi4KdHqIis7juCq" +
            "aK869v+dDxqHGIsF3j7aGRCzrRogaCOXdk6YKkc+SEUYgYUviZadkRQ9QZza643B8nzvcO4tySkBzVif7fhqCNzVHSZdF3nM" +
            "mzLb/95PDxvKFluxuTvqB6CmsiWAIVTT8YSwSuNpxvDDCcVuuNE8WXh30h+7Sapl+hUZOFZcMMupp9lvOgVAEbrWdUKvE+iV" +
            "yMB6YoprpTY0tOExrARS/rV9rv0n5vkGjrfzmS5NlNdnP6RDDSLdh4+QROKGvB4Ao+zOtgrY0OB7fw6TKDlGiKLpHOSa1F+M" +
            "bCv3dIvfvVP2TF4sUJLPxKFXYWACN571VQyogmZLY+davlH8q3PH5YMzZH4LEnL7JL/CNXH0bQMKMcvCbttKAMzojCUYDMlY" +
            "+Gfla94++TpPiBbafR/675I4D5aKhp6BVosDKprWzfy6DQekNIA3f489YVlfUlApzni+sFcGLRJiVa3B/4K4BMUIb2C9cqxe" +
            "Di/tAifcQUunXeaT0ef0ftJ51B4rTq/GTKbdAf0QriylMrexQ8SXNtmhtPvH9x3PGYRsaFGfPy6zVHAoypAaNVP1mIcJF5Gr" +
            "ueqiau4RMPHkjpmgg8A5Wm1139eyIZ189iYjo0XpuxNzaZQkZewcBdUiM6h6FGbjv5VCG3TwcVxG602p0PK8ZEk74VvY00eF" +
            "dne2QIniFSAL87X+SJuNw+BjezyqRJzIbiA25VMYXqZlMekHkdbOTSjqfnX2TJbkjbhPJO0b2tvx3F3Ztu84EskRX30E4Ebr" +
            "qLFByIk5xN5Oy7nXBZ6PeNEwjB96ctjAvhZE6A6Oi1tcnbxDxw9HFPeUbS4NNCNJmLc9Z4Xd+R4GPLqkKjVY/mKwWmpWGQx0" +
            "g5Iy/MXBKbSBA71QrHAL4Zs6ae4cGp8I01lKfD5L8AprAuOGs3nUf/MB3xDNwqVo5uxxiq9AgqO/gKv6HRPVY6kVL1JsAPjP" +
            "0potmQmqoBeE/f/y9MyQIiwzKyc7opU/UWB7N4euJvuXVJNzxkjKVUJXstB3uyXired2w29mnKf1ZKG1iCFFYURy3Vf+BDBF" +
            "7YhlDNpxvXezXo8NBe+ifmfglTSRBhIUpfSxjtttEx0hXKcb9sFiDtEe/Q+rZsPMf4To4oytoU4lKSI9mzE1rHU5X24o9Ymg" +
            "I5fclK4ZB6Tx/Irzniz6wnjNo+mSqWFor7v7aktvhi+dfZlaxFvIRrzeTFkr7Hm1cHsm5Jjq+EJBKoO21NXjFTjrYC5QqF0W" +
            "5wlrP8BDn9hPxqa/ytCHN7fZQMWBdguQU9f/0jYcuOFRc8cfSOUK7rJNUpNJGskBYyD5mi1HAzqCEd8+1s50fErmsBiFVQCA" +
            "VGRsvgJ6WBc88o2cJ7rLzzNplrn3EIvTtKoIMlbwJDv6XDEuoL44Ahr92YFjObOcsC3Fwfg2lodwCB1Sbl60Zl+PigrsQBK6" +
            "xNx2fhuINNVNJzAJKmmQ8xBDC8NHuJlY70LkAHlbFc0WPOuy3VnY9XyLmgHTvc9K2sA9jcxFtaxJytKVA+01YaJaHFfhMiRq" +
            "394f6SBLvIngkkjycXruLOYhv3PUtlNGUc5MwneXUJNlQSWMsaVg8aOYYmvHcuOpJpTI8Pb7+YATpK4NnSme1v8iqoMzf2RV" +
            "O5GmPyMvNyinhkSrjnXo4myhxskU2wX3y/wEaFYrEa1n0RcZ/q+EuwybHhjqbT6f5Q90qFS5B4V70H23gucGbw70Tzp4Tl3X" +
            "mklfEdkhZyx4lk4aMrGp7goBlVeb6TOJWzDH8qSlZJKmIqOObUeQyQIgbraUOZ97tz7O16G7RvaoxrQxB/DhemDzT66/pw0F" +
            "lztpwST08XE8w+IjazhwuFES64g2XEtyGELI52GGovrbxUN5gSdKVRUlzx0Lc2Ypg03t/MtWvrovwnz+nnQP05EWReR34GVj" +
            "AzUmrHWPNEH5nH0UAKsGzG+gfowX2r2y9Q6Tmdz9P9CF1P/AHKpsYi1Qatawh38T5lLlrWjf1XaNgIL7Xe+zi1hUTFNA6t1E" +
            "SAQfLoRZ0fgM7CvoKrU3ua/NKD2dWsQIvAmY0tjjGRDK3huKHjpe9ywBKa0fRuLI4TmNrxD0G7ZBWDixyXkuNDu+J0lu9Yh/" +
            "0J4VxuijVq7BlfcZJmG9PhrYhY68BhRmSH3Uv+sdKypHaJfNLXXuCcz2VErF2g6oQJKaqummhPxicwzCMTVE2cAh73yCijAo" +
            "5k4YtH7+q3ttrLNM/zfkt2QH3p3E/bnT8QPgLzI9mFUcFnqBsF9TcnBPClvj7ZMl5Vmi3/CcPwjzcaBNgFwR+8prHpnq7Phv" +
            "qSOMurvO+gDym3YTiUOPJKRng2O4NqU6p7IgQkuHEtUXXTOGlp9XbJQFRVHReJG1aiJp3Vr551ANdAIPPATSYMPc19tSy89l" +
            "kKHHi153C9apLF4w4nlon09Wpi9u3iM5Lva4muMHoQwWO7o+UQjf9WpfqMMK/D08zw2ZkhGrcQOC1g7gdjEpqonH0QK0/7lB" +
            "ZHXVGyImzlOFV72Nsf7rk+HbXUPN0r8Zf1DagGI6HvkQc4rJ6tPErrt6W6Qg6KDzWfGjD+lpbLw212v4nZU/J07yyLWL5x8o" +
            "WGdMHfr0MoQBC5ZtSKdlRBTmOPcqJUKPjOUEYVSeM5g0vq2b2awX7Xzdjgn7/XjvZuRat0uX7AYSg0ZSb8aihkoAkSSIgXtA" +
            "pbBVN5BcwgVws3SUIa8tsraHnNBgScEcy9TMwNxFcthjGhgVEyt3xTV9yn7uTUfw+djUOwrxnZfeE7a5pGuIeoO0F3tUKdJu" +
            "rhhmaNCBxPvkc2dhEpXgQXCa1wvGK/p4rwTIApj9EHmLcUUwMQeoIl6ZDMDJqzkssS69M+gI7C8+GvNa2s6OH+fcFB0NuNac" +
            "61mPt4SJ/4bbbHLRVuKp4V2A/NUATCob7kRA2VBcV0g9kH+bJAayakNpzZQmooqn9AN+5cKsNbC/pfJCOrPTyrU26q2SfB5K" +
            "Jd0oY02eFVuhoJZgNF/2w+2fjTcFDlORI4VRTsHffUeCZf6mRhzjzFLPvrpJh/jpdw8tYiERGcvwIHX1P5PFbaO7AQn3ZKpL" +
            "WDJ2TxZVjO88b7x0xzgn5sD6fGLs8544XnH7oUMbP9hFVPQ6AwfvcqR2nKyQ38qyeNCCLshITZ0X9krZvLQeBjFSq+jL8uWP" +
            "mlt6hQHJgdIP15m7wiaALTcamx9wKf7UiA1/EcNYSb5ud4cOT/8CGKP3L8FXEAiLqObwI5XemGBLfoniK90cHe4suLMwilAi" +
            "hJF0FrF94yRRklW1AI4MkzOiZ3NO54OnayGwBamgWmFCOzk0MgpW5BRc61/PbGbRl6a98UFo4D3q9e3h/WRT+SAqt0xphkRl" +
            "NccZ1gsEY65v0+mUqsY+CXlGbTzb1ROlXfyvKNrcWc5HxXuWarbNJ63EJUB1vxK5FZ+MuviNNsyfihh6c78q7Zxfu1uADp0C" +
            "rD19aelAqY0vZQu+rqdvVDVMOjcEPOpYUhpR5WLB32iomf+zZk8z7vvk7+Nq8/ddJC5CuYhna0rJO9gXCgWgbd1hmufIpAcw" +
            "SHcyY9vVqx3yUyah0tTAV8tJmHW4ZCnDyqNOK7F7txyRG7SCg/bCOPTObHL94jaQf1Cv9RVN1jFaSzT6CQ184XiqopLRnrzE" +
            "3nYgjEbGk0P4GddEurIIEFw/5qX8xYHrVZSLdMcP3I/ZAbWXKMwjjhQ5EZUnftrwA4YfcVbNsEd5YACJ8UEWDPmtzyEeWYUG" +
            "6KYt/tCbbpZwReyH0yUTEiLgvbaEPixeHi4m9EgwEl12uMfWbfCBhXkj3PO9WsGZ/uBCeBy6bnH4BxjZA1CDSylqs9BnDUlw" +
            "yFuVdJyEPjYArPpSzx9KygWM7PWAms19/ZMKj8s8QdoZnbWYfFbyqxs5jVUCr0CkOjFsrtKgsggLYMn8np+pX3KhKmQa4hdc" +
            "rUMhdYoJ1ZIyh+mj2OMrIuXxsSABJcxl1zfTEI4Rggz2lAYTYaYz/29jaHfRe3/mP3MVJGK/w+pp3Zbe5FNN7ru2wLnUZrCI" +
            "7777xJEnWVdrFu1RvIsoRJtUt0XhLImGNc6iqMbn6wQOOJcdtE56D6fCL0aQO/c9+RTFR0+l6DQtqt9+20xYXg==";
        return Convert.FromBase64String(table);
    }
}
