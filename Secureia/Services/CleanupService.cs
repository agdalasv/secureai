using System.IO;
namespace Secureia.Services;

public class CleanupService
{
    public event Action<string>? StatusChanged;
    public event Action<int>? ProgressChanged;

    public async Task<CleanupResult> RunCleanupAsync()
    {
        var result = new CleanupResult();
        await Task.Run(() =>
        {
            result.BytesFreed += CleanTempFiles();
            ProgressChanged?.Invoke(25);
            StatusChanged?.Invoke("Limpiando caché del navegador...");

            result.BytesFreed += CleanBrowserCache();
            ProgressChanged?.Invoke(50);
            StatusChanged?.Invoke("Limpiando archivos temporales del sistema...");

            result.BytesFreed += CleanSystemTemp();
            ProgressChanged?.Invoke(75);
            StatusChanged?.Invoke("Liberando memoria...");

            ClearStandbyMemory();
            ProgressChanged?.Invoke(100);
            StatusChanged?.Invoke("Limpieza completada.");
        });
        return result;
    }

    public CleanupResult RunCleanupSync()
    {
        var result = new CleanupResult();
        result.BytesFreed += CleanTempFiles();
        result.BytesFreed += CleanBrowserCache();
        result.BytesFreed += CleanSystemTemp();
        return result;
    }

    private long CleanTempFiles()
    {
        long freed = 0;
        var tempDirs = new[]
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.InternetCache)
        };

        foreach (var dir in tempDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.*", SearchOption.TopDirectoryOnly))
                {
                    try { freed += new FileInfo(file).Length; File.Delete(file); }
                    catch { }
                }
            }
            catch { }
        }
        return freed;
    }

    private long CleanBrowserCache()
    {
        long freed = 0;
        var chromeCache = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Google\\Chrome\\User Data\\Default\\Cache");
        var edgeCache = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Microsoft\\Edge\\User Data\\Default\\Cache");

        foreach (var dir in new[] { chromeCache, edgeCache })
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.*", SearchOption.AllDirectories))
                {
                    try { freed += new FileInfo(file).Length; File.Delete(file); }
                    catch { }
                }
            }
            catch { }
        }
        return freed;
    }

    private long CleanSystemTemp()
    {
        long freed = 0;
        var systemTemp = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
        if (!Directory.Exists(systemTemp)) return freed;

        try
        {
            foreach (var file in Directory.EnumerateFiles(systemTemp, "*.*", SearchOption.TopDirectoryOnly))
            {
                try { freed += new FileInfo(file).Length; File.Delete(file); }
                catch { }
            }
        }
        catch { }
        return freed;
    }

    private void ClearStandbyMemory()
    {
        try
        {
            using var process = new System.Diagnostics.Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c echo EmptyWorkingSet > NUL";
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.UseShellExecute = false;
            process.Start();
            process.WaitForExit(1000);
        }
        catch { }
    }
}

public class CleanupResult
{
    public long BytesFreed { get; set; }
    public string FormattedFreed => FormatBytes(BytesFreed);

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
        return $"{bytes / (1024.0 * 1024 * 1024):F1} GB";
    }
}
