using System.IO;
using System.Text;
using Secureia.Models;

namespace Secureia.Services;

public class UsbScanner
{
    private readonly ScanEngine _scanEngine;
    private readonly TtsService? _tts;
    private readonly LogService? _log;
    private readonly ExpertMalwareAI? _expertMalware;
    private readonly HashSet<string> _knownDrives = new();
    private bool _isScanning;

    public event Action<int, int>? ScanProgress;
    public event Action<string>? ScanStatus;
    public event Action<ScanResult>? ThreatFound;
    public event Action<string>? UsbInserted;

    public UsbScanner(ScanEngine scanEngine, TtsService? tts = null,
                      LogService? log = null, ExpertMalwareAI? expertMalware = null)
    {
        _scanEngine = scanEngine;
        _tts = tts;
        _log = log;
        _expertMalware = expertMalware;

        foreach (var drive in DriveInfo.GetDrives())
        {
            if (drive.DriveType == DriveType.Removable && drive.IsReady)
                _knownDrives.Add(drive.Name.ToUpperInvariant());
        }
    }

    public void PollForNewDrives()
    {
        foreach (var drive in DriveInfo.GetDrives())
        {
            if (drive.DriveType != DriveType.Removable || !drive.IsReady) continue;
            var name = drive.Name.ToUpperInvariant();
            if (_knownDrives.Add(name))
                HandleUsbInsertion(name);
        }
    }

    private void HandleUsbInsertion(string drivePath)
    {
        try
        {
            var di = new DriveInfo(drivePath.TrimEnd('\\'));
            var label = string.IsNullOrEmpty(di.VolumeLabel) ? "USB" : di.VolumeLabel;
            var msg = $"USB detectado: {label} ({drivePath}) - iniciando escaneo automático";
            UsbInserted?.Invoke(msg);
            ScanStatus?.Invoke(msg);
            _log?.Log(new LogEntry
            {
                Event = $"USB insertado: {label} ({drivePath})",
                ActionTaken = "Escaneo automático",
                User = Environment.UserName
            });
            _tts?.Speak($"USB detectado. Iniciando escaneo de {label}.");

            _ = ScanUsbDriveAsync(drivePath, label);
        }
        catch { }
    }

    public async Task<UsbScanResult> ScanUsbDriveAsync(string drivePath, string? label = null)
    {
        var result = new UsbScanResult
        {
            DrivePath = drivePath,
            Label = label ?? "USB",
            StartedAt = DateTime.Now
        };

        if (_isScanning)
        {
            ScanStatus?.Invoke("Ya hay un escaneo de USB en progreso.");
            return result;
        }

        _isScanning = true;

        try
        {
            ScanStatus?.Invoke($"Recopilando archivos en {drivePath}...");
            var files = await Task.Run(() => GetUsbFiles(drivePath));
            result.TotalFiles = files.Count;
            ScanStatus?.Invoke($"Escaneando {files.Count} archivos en USB...");

            int processed = 0;
            var deepAnalyzer = new DeepAnalyzer();

            foreach (var file in files)
            {
                if (string.IsNullOrEmpty(file)) continue;

                try
                {
                    var fi = new FileInfo(file);
                    if (fi.Length > 100 * 1024 * 1024) continue;

                    var extension = Path.GetExtension(file).ToLowerInvariant();
                    if (extension == ".exe" || extension == ".dll" || extension == ".scr" ||
                        extension == ".ps1" || extension == ".vbs" || extension == ".bat" ||
                        extension == ".cmd" || extension == ".js" || extension == ".jar" ||
                        extension == ".msi")
                    {
                        var deepResults = deepAnalyzer.AnalyzeDeep(file);
                        foreach (var dr in deepResults)
                        {
                            result.ThreatsFound++;
                            ThreatFound?.Invoke(dr);
                            _log?.Log(new LogEntry
                            {
                                Event = $"[USB] Amenaza detectada en {label}: {dr.ThreatName}",
                                FilePath = file,
                                ActionTaken = "Alerta USB",
                                User = Environment.UserName
                            });
                            _expertMalware?.AnalyzeFile(file);
                        }
                    }

                    if (IsSuspiciousFileName(file))
                    {
                        result.SuspiciousFiles++;
                        var msg = $"[USB] Archivo sospechoso: {Path.GetFileName(file)} en {label}";
                        _log?.Log(new LogEntry
                        {
                            Event = msg,
                            FilePath = file,
                            ActionTaken = "Alerta USB",
                            User = Environment.UserName
                        });
                    }

                    if (HasAutorunInfection(drivePath, file))
                    {
                        result.ThreatsFound++;
                        var msg = $"[USB] Infección por autorun detectada en {label}";
                        _log?.Log(new LogEntry
                        {
                            Event = msg,
                            FilePath = file,
                            ActionTaken = "Alerta USB crítica",
                            User = Environment.UserName
                        });
                    }
                }
                catch { }

                processed++;
                ScanProgress?.Invoke(processed, files.Count);
            }

            result.CompletedAt = DateTime.Now;
            result.IsClean = result.ThreatsFound == 0 && result.SuspiciousFiles == 0;

            if (result.IsClean)
            {
                ScanStatus?.Invoke($"USB {label} escaneado: sin amenazas ({files.Count} archivos)");
                _tts?.Speak($"USB {label} escaneado. Sin amenazas.");
            }
            else
            {
                var threatMsg = $"USB {label}: {result.ThreatsFound} amenazas, {result.SuspiciousFiles} sospechosos";
                ScanStatus?.Invoke($"Escaneo USB completado: {threatMsg}");
                _tts?.Speak($"Se encontraron {result.ThreatsFound} amenazas en el USB {label}.");
            }
        }
        catch (Exception ex)
        {
            ScanStatus?.Invoke($"Error escaneando USB: {ex.Message}");
        }
        finally
        {
            _isScanning = false;
        }

        return result;
    }

    private static List<string> GetUsbFiles(string drivePath)
    {
        var files = new List<string>();
        try
        {
            var dirs = new Stack<string>();
            dirs.Push(drivePath);
            while (dirs.Count > 0)
            {
                var currentDir = dirs.Pop();
                try
                {
                    foreach (var dir in Directory.EnumerateDirectories(currentDir))
                        dirs.Push(dir);
                    foreach (var file in Directory.EnumerateFiles(currentDir))
                        files.Add(file);
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        catch { }
        return files;
    }

    private static bool IsSuspiciousFileName(string filePath)
    {
        var name = Path.GetFileNameWithoutExtension(filePath)?.ToLowerInvariant() ?? "";
        var extension = Path.GetExtension(filePath)?.ToLowerInvariant() ?? "";

        var dangerousExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".jar",
            ".vbe", ".jse", ".wsf", ".wsh", ".msi", ".msp", ".com", ".pif",
            ".application", ".hta", ".cpl", ".gadget"
        };

        if (!dangerousExtensions.Contains(extension)) return false;

        var suspiciousKeywords = new[]
        {
            "invoice", "receipt", "urgent", "password", "account", "bank",
            "paypal", "crack", "keygen", "patch", "activator", "download",
            "photo", "image", "document", "important", "confidential",
            "salary", "bonus", "payment", "transfer", "wire", "ach",
            "usb", "flash", "pendrive", "autorun", "click", "doubleclick",
            "setup", "install", "update", "flash", "player", "codec"
        };

        return suspiciousKeywords.Any(k => name.Contains(k));
    }

    private static bool HasAutorunInfection(string drivePath, string filePath)
    {
        var fileName = Path.GetFileName(filePath)?.ToLowerInvariant() ?? "";
        if (fileName == "autorun.inf")
        {
            try
            {
                var content = File.ReadAllText(filePath, Encoding.UTF8);
                return content.Contains("open=", StringComparison.OrdinalIgnoreCase) ||
                       content.Contains("action=", StringComparison.OrdinalIgnoreCase) ||
                       content.Contains("shell\\", StringComparison.OrdinalIgnoreCase);
            }
            catch { }
        }

        var hiddenFiles = new[] { "desktop.ini", "thumbs.db", "recycle.bin", "system volume information" };
        return hiddenFiles.Any(h => fileName.Contains(h, StringComparison.OrdinalIgnoreCase) &&
                                    new FileInfo(filePath).Length > 1024 * 1024);
    }

    public void Dispose()
    {
    }
}

public class UsbScanResult
{
    public string DrivePath { get; set; } = "";
    public string Label { get; set; } = "";
    public DateTime StartedAt { get; set; }
    public DateTime CompletedAt { get; set; }
    public int TotalFiles { get; set; }
    public int ThreatsFound { get; set; }
    public int SuspiciousFiles { get; set; }
    public bool IsClean { get; set; }
}
