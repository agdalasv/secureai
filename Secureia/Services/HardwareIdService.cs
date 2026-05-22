using System.Management;
using System.Security.Cryptography;
using System.Text;

namespace Secureia.Services;

public static class HardwareIdService
{
    private static string? _cachedId;

    public static string GenerateHardwareId()
    {
        if (_cachedId != null) return _cachedId;

        try
        {
            var components = new List<string>();

            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor");
                foreach (var obj in searcher.Get())
                    components.Add(obj["ProcessorId"]?.ToString() ?? "");
            }
            catch { }

            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BaseBoard");
                foreach (var obj in searcher.Get())
                    components.Add(obj["SerialNumber"]?.ToString() ?? "");
            }
            catch { }

            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_DiskDrive WHERE Index=0");
                foreach (var obj in searcher.Get())
                    components.Add(obj["SerialNumber"]?.ToString() ?? "");
            }
            catch { }

            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT MACAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True");
                foreach (var obj in searcher.Get())
                    components.Add(obj["MACAddress"]?.ToString() ?? "");
            }
            catch { }

            var raw = string.Join("|", components.Where(c => !string.IsNullOrEmpty(c)));
            if (string.IsNullOrEmpty(raw))
                raw = Environment.MachineName + "|" + Environment.UserName + "|" + Environment.OSVersion.VersionString;

            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(raw));
            var id = Convert.ToHexString(hash).ToLowerInvariant();
            _cachedId = id;
            return id;
        }
        catch
        {
            var fallback = Convert.ToHexString(SHA256.HashData(
                Encoding.UTF8.GetBytes(Environment.MachineName + "|" + Environment.UserName))).ToLowerInvariant();
            _cachedId = fallback;
            return fallback;
        }
    }
}
