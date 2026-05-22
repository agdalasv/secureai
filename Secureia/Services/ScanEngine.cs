using System.Collections.Concurrent;
using System.IO;
using System.IO.Compression;
using Secureia.Models;

namespace Secureia.Services;

public class ScanEngine
{
    private readonly DefinitionService? _defService;
    private readonly ThreatDatabase? _threatDb;

    public ScanEngine(DefinitionService? defService = null, ThreatDatabase? threatDb = null)
    {
        _defService = defService;
        _threatDb = threatDb;
    }
    public event Action<ScanResult>? ThreatDetected;
    public event Action<int, int>? ProgressChanged;
    public event Action<string>? StatusChanged;
    public bool IsScanning { get; private set; }
    public CancellationTokenSource? CancelToken { get; private set; }
    public int RansomwareFound { get; private set; }
    public int BloatwareFound { get; private set; }
    public int RootkitsFound { get; private set; }
    public int AdvancedThreatsFound { get; private set; }

    private static readonly HashSet<string> DangerousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".jar",
        ".vbe", ".jse", ".wsf", ".wsh", ".msi", ".msp", ".com", ".pif",
        ".gadget", ".application", ".hta", ".cpl", ".msc", ".vb", ".jsp"
    };

    private static readonly HashSet<string> SuspiciousNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "invoice", "receipt", "urgent", "password",
        "account", "bank", "paypal", "crack", "keygen", "patch", "activator"
    };

    private static readonly HashSet<string> SafeDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
        "C:\\ProgramData\\Microsoft", "C:\\$Recycle.Bin", "C:\\System Volume Information"
    };

    private static readonly HashSet<string> KnownBloatwarePaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "%LOCALAPPDATA%\\Temp\\asw", "%LOCALAPPDATA%\\Avg",
        "%ProgramFiles(x86)%\\IObit", "%ProgramFiles%\\IObit",
        "%ProgramFiles(x86)%\\Glarysoft", "%ProgramFiles%\\Glarysoft",
        "%ProgramFiles(x86)%\\WiseCleaner", "%ProgramFiles%\\WiseCleaner",
        "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Extensions\\honey"
    };

    private static readonly HashSet<string> RootkitIndicatorFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "C:\\Windows\\System32\\drivers\\capcom.sys",
        "C:\\Windows\\System32\\drivers\\gdrv.sys",
        "C:\\Windows\\System32\\drivers\\kprocesshacker.sys",
        "C:\\Windows\\System32\\drivers\\pchunter.sys",
        "C:\\Windows\\System32\\drivers\\powerkiller.sys"
    };

    private static readonly string[] DeauthAttackTools =
    {
        "aireplay", "mdk3", "mdk4", "reaver", "wash", "besside",
        "wifite", "airgeddon", "fluxion", "linset", "bully",
        "pixiewps", "aircrack", "airmon", "airodump"
    };

    private static readonly string[] DoSToolNames =
    {
        "hping", "hping3", "slowloris", "goldeneye", "LOIC", "HOIC",
        "tor hammer", "pyloris", "slowhttptest", "siege", "httping",
        "mausezahn", "t50", "dstat", "dnrd", "dos", "drdos",
        "stress", "bombard", "flood", "syn flood", "udp flood"
    };

    private static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".cab", ".tgz", ".bz2"
    };

    public async Task<List<ScanResult>> ScanDirectoryAsync(string directory, CancellationToken? token = null)
    {
        IsScanning = true;
        RansomwareFound = 0;
        BloatwareFound = 0;
        RootkitsFound = 0;
        AdvancedThreatsFound = 0;
        CancelToken = CancellationTokenSource.CreateLinkedTokenSource(token ?? CancellationToken.None);
        var results = new ConcurrentBag<ScanResult>();

        StatusChanged?.Invoke($"Recopilando archivos desde {directory}...");

        var files = await Task.Run(() => GetFilesRecursive(directory));

        var total = files.Count;
        var processed = 0;

        if (total == 0)
        {
            IsScanning = false;
            StatusChanged?.Invoke("No se encontraron archivos para escanear (permisos insuficientes).");
            return new List<ScanResult>();
        }

        StatusChanged?.Invoke($"Escaneando {total} archivos...");

        var parallelOptions = new ParallelOptions
        {
            CancellationToken = CancelToken.Token,
            MaxDegreeOfParallelism = Environment.ProcessorCount
        };

        await Task.Run(() =>
        {
            Parallel.ForEach(files, parallelOptions, file =>
            {
                if (CancelToken.IsCancellationRequested) return;

                var result = AnalyzeFile(file);
                if (result != null)
                {
                    results.Add(result);
                    ThreatDetected?.Invoke(result);
                }

                Interlocked.Increment(ref processed);
                ProgressChanged?.Invoke(processed, total);
            });
        });

        IsScanning = false;
        StatusChanged?.Invoke($"Escaneo completado. {results.Count} amenazas encontradas.");
        return results.ToList();
    }

    public void Cancel()
    {
        CancelToken?.Cancel();
        IsScanning = false;
    }

    private List<string> GetFilesRecursive(string root)
    {
        var result = new List<string>();
        var appDir = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');

        try
        {
            var dirs = new Stack<string>();
            dirs.Push(root);

            while (dirs.Count > 0)
            {
                if (CancelToken?.IsCancellationRequested == true) break;

                var currentDir = dirs.Pop();

                if (currentDir.TrimEnd('\\').Equals(appDir, StringComparison.OrdinalIgnoreCase))
                    continue;

                var skip = false;
                foreach (var safe in SafeDirectories)
                {
                    if (currentDir.StartsWith(safe, StringComparison.OrdinalIgnoreCase))
                    { skip = true; break; }
                }
                if (skip) continue;

                try
                {
                    foreach (var dir in Directory.EnumerateDirectories(currentDir))
                    {
                        dirs.Push(dir);
                    }

                    foreach (var file in Directory.EnumerateFiles(currentDir))
                    {
                        result.Add(file);
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (System.IO.IOException) { }
            }
        }
        catch { }
        return result;
    }

    public async Task<List<ScanResult>> DeepScanDirectoryAsync(string directory, CancellationToken? token = null)
    {
        IsScanning = true;
        RansomwareFound = 0;
        BloatwareFound = 0;
        RootkitsFound = 0;
        AdvancedThreatsFound = 0;
        CancelToken = CancellationTokenSource.CreateLinkedTokenSource(token ?? CancellationToken.None);
        var results = new ConcurrentBag<ScanResult>();

        StatusChanged?.Invoke($"Recopilando archivos desde {directory}...");

        var files = await Task.Run(() => GetFilesRecursive(directory));
        var total = files.Count;
        var processed = 0;

        if (total == 0)
        {
            IsScanning = false;
            StatusChanged?.Invoke("No se encontraron archivos.");
            return new List<ScanResult>();
        }

        StatusChanged?.Invoke($"Análisis profundo de {total} archivos...");

        var parallelOptions = new ParallelOptions
        {
            CancellationToken = CancelToken.Token,
            MaxDegreeOfParallelism = Environment.ProcessorCount
        };

        var deepAnalyzer = new DeepAnalyzer(_defService, _threatDb);

        await Task.Run(() =>
        {
            Parallel.ForEach(files, parallelOptions, file =>
            {
                if (CancelToken.IsCancellationRequested) return;

                var result = AnalyzeFile(file);
                if (result != null)
                {
                    results.Add(result);
                    ThreatDetected?.Invoke(result);
                }

                var extension = Path.GetExtension(file).ToLowerInvariant();
                if (ArchiveExtensions.Contains(extension) || extension == ".exe" || extension == ".dll")
                {
                    var deepResults = deepAnalyzer.AnalyzeDeep(file);
                    foreach (var dr in deepResults)
                    {
                        results.Add(dr);
                        ThreatDetected?.Invoke(dr);
                    }
                }

                Interlocked.Increment(ref processed);
                ProgressChanged?.Invoke(processed, total);
            });
        });

        IsScanning = false;
        StatusChanged?.Invoke($"Escaneo profundo completado. {results.Count} amenazas encontradas.");
        return results.ToList();
    }

    private ScanResult? AnalyzeFile(string filePath)
    {
        var fileName = Path.GetFileNameWithoutExtension(filePath).ToLower();
        var extension = Path.GetExtension(filePath).ToLower();
        var threats = new List<string>();

        if (!File.Exists(filePath)) return null;

        var fileInfo = new FileInfo(filePath);
        if (fileInfo.Length > 200 * 1024 * 1024) return null;

        if (_defService?.IsKnownThreat(filePath) == true)
            threats.Add("[Base de datos] Coincide con amenaza conocida");

        if (_threatDb?.IsBloatware(fileName) == true || IsBloatwareByPath(filePath))
        {
            threats.Add("[Bloatware/PUP] Aplicación potencialmente no deseada");
        }

        if (_threatDb?.IsKnownRootkitDriver(Path.GetFileName(filePath)) == true ||
            RootkitIndicatorFiles.Contains(filePath, StringComparer.OrdinalIgnoreCase))
        {
            threats.Add("[Rootkit] Controlador o archivo de rootkit conocido");
        }

        if (IsDeauthTool(fileName))
        {
            threats.Add("[Deauth] Herramienta de desautenticación Wi-Fi detectada");
        }

        if (IsDoSTool(fileName))
        {
            threats.Add("[DoS/DDoS] Herramienta de ataque de denegación de servicio detectada");
        }

        if (DangerousExtensions.Contains(extension))
        {
            foreach (var keyword in SuspiciousNames)
            {
                if (fileName.Contains(keyword))
                    threats.Add($"[Heurístico] Nombre sospechoso: contiene '{keyword}'");
            }

            var packerDetected = IsPackedExecutable(filePath);
            if (extension == ".exe")
            {
                if (packerDetected)
                    threats.Add("[Heurístico] Ejecutable empaquetado/compresor detectado");

                if (HasSuspiciousImports(filePath))
                    threats.Add("[Heurístico] Importaciones de API peligrosas detectadas");
            }

            if (extension == ".dll" && packerDetected)
                threats.Add("[Heurístico] DLL empaquetada con compresor sospechoso");

            if (extension == ".scr" && packerDetected)
                threats.Add("[Heurístico] Screensaver empaquetado sospechoso");
        }

        if (threats.Count == 0) return null;

        var isKnownThreat = threats.Any(t => t.Contains("Base de datos"));
        var isRootkit = threats.Any(t => t.Contains("Rootkit"));

        if (!isKnownThreat && !isRootkit && threats.Count < 2)
            return null;

        if (!isKnownThreat && !isRootkit && threats.Count == 2)
        {
            var allHeuristic = threats.All(t => t.Contains("Heurístico"));
            if (allHeuristic)
                return null;
        }

        var level = (isKnownThreat || isRootkit, threats.Count) switch
        {
            (true, _) => ThreatLevel.High,
            (_, >= 3) => ThreatLevel.High,
            (_, 2) => ThreatLevel.Medium,
            _ => ThreatLevel.Low
        };

        return new ScanResult
        {
            FilePath = filePath,
            ThreatName = string.Join("; ", threats),
            Level = level,
            Description = $"El archivo {filePath} presenta características sospechosas: {string.Join(", ", threats)}",
            DetectedAt = DateTime.Now
        };
    }

    private bool IsBloatwareByPath(string filePath)
    {
        var path = filePath.ToLowerInvariant();
        foreach (var bp in KnownBloatwarePaths)
        {
            var expanded = Environment.ExpandEnvironmentVariables(bp).ToLowerInvariant();
            if (path.StartsWith(expanded, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private bool IsDeauthTool(string fileName)
    {
        return DeauthAttackTools.Any(t => fileName.Contains(t, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsDoSTool(string fileName)
    {
        return DoSToolNames.Any(t => fileName.Contains(t, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsPackedExecutable(string filePath)
    {
        try
        {
            using var stream = File.OpenRead(filePath);
            if (stream.Length < 256) return false;
            var header = new byte[1024];
            stream.Read(header, 0, header.Length);
            var text = System.Text.Encoding.ASCII.GetString(header);

            return text.Contains("UPX") || text.Contains("ASPack") ||
                   text.Contains("Armadillo") || text.Contains("Themida") ||
                   text.Contains("MPRESS") || text.Contains("Enigma") ||
                   text.Contains("VMProtect") || text.Contains("Obsidium");
        }
        catch { return false; }
    }

    private bool HasSuspiciousImports(string filePath)
    {
        try
        {
            using var stream = File.OpenRead(filePath);
            if (stream.Length < 4096) return false;
            var buffer = new byte[16384];
            stream.Read(buffer, 0, buffer.Length);
            var text = System.Text.Encoding.ASCII.GetString(buffer);

            var susp = new[] { "WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx",
                               "SetWindowsHookEx", "GetAsyncKeyState", "NtUnmapViewOfSection",
                               "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
                               "MiniDumpWriteDump", "ReadProcessMemory", "OpenProcess" };

            var count = susp.Count(s => text.Contains(s));
            return count >= 4;
        }
        catch { return false; }
    }
}
