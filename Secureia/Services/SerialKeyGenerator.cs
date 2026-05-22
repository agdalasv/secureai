using System.Security.Cryptography;
using System.Text;

namespace Secureia.Services;

public static class SerialKeyGenerator
{
    private const string ValidChars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private const int GroupSize = 5;
    private const int GroupCount = 6;
    private const int RawLength = 25;
    private const int TotalLength = 30;

    private static readonly byte[] SecretKey =
        Encoding.UTF8.GetBytes("S3cur3AI-P1us-2K26-K3y!@#");

    public static string GenerateKey()
    {
        var random = RandomNumberGenerator.GetBytes(RawLength);
        var sb = new StringBuilder(RawLength);
        foreach (var b in random)
            sb.Append(ValidChars[b % ValidChars.Length]);

        var raw = sb.ToString();

        using var hmac = new HMACSHA256(SecretKey);
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(raw));

        var csChars = new char[GroupSize];
        for (int i = 0; i < GroupSize; i++)
            csChars[i] = ValidChars[hash[i] % ValidChars.Length];
        var checksum = new string(csChars);

        return FormatKey(raw + checksum);
    }

    public static bool ValidateKey(string key)
    {
        var clean = key.Replace("-", "").Trim().ToUpperInvariant();
        if (clean.Length != TotalLength) return false;

        var raw = clean.Substring(0, RawLength);
        var checksum = clean.Substring(RawLength, GroupSize);

        if (raw.Any(c => !ValidChars.Contains(c))) return false;
        if (checksum.Any(c => !ValidChars.Contains(c))) return false;

        using var hmac = new HMACSHA256(SecretKey);
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(raw));

        for (int i = 0; i < GroupSize; i++)
        {
            if (checksum[i] != ValidChars[hash[i] % ValidChars.Length])
                return false;
        }

        return true;
    }

    private static string FormatKey(string raw)
    {
        var parts = new List<string>();
        for (int i = 0; i < raw.Length; i += GroupSize)
            parts.Add(raw.Substring(i, GroupSize));
        return string.Join("-", parts);
    }
}
