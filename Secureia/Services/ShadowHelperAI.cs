using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Secureia.Models;

namespace Secureia.Services;

public class ShadowHelperAI
{
    private readonly TtsService? _tts;
    private readonly LogService? _log;
    private readonly DefinitionService? _defService;
    private readonly ThreatDatabase? _threatDb;
    private readonly DeepAnalyzer? _deepAnalyzer;

    private bool _isActive;
    private bool _isBusy;
    private int _remainingQuota;
    private DateTime _lastActivation = DateTime.MinValue;
    private readonly Dictionary<string, DateTime> _scanCache = new();
    private readonly HashSet<string> _scannedDirs = new();
    private CancellationTokenSource? _workCts;

    private const int MaxQuota = 5;
    private const int CooldownSeconds = 120;

    public bool IsActive => _isActive;
    public bool IsBusy => _isBusy;
    public int RemainingQuota => _remainingQuota;

    public event Action<string>? ShadowAlert;
    public event Action<string, ThreatLevel>? ThreatFound;
    public event Action<ScanResult>? ScanResultFound;
    public event Action<string>? StatusChanged;

    public ShadowHelperAI(TtsService? tts = null, LogService? log = null,
                          DefinitionService? defService = null, ThreatDatabase? threatDb = null,
                          DeepAnalyzer? deepAnalyzer = null)
    {
        _tts = tts;
        _log = log;
        _defService = defService;
        _threatDb = threatDb;
        _deepAnalyzer = deepAnalyzer;
    }

    public void Activate()
    {
        if (_isActive) return;

        var now = DateTime.Now;
        if ((now - _lastActivation).TotalSeconds < CooldownSeconds)
        {
            ShadowAlert?.Invoke("[Shadow AI] En espera - respetando intervalo entre activaciones");
            return;
        }

        _isActive = true;
        _remainingQuota = MaxQuota;
        _lastActivation = now;
        _workCts = new CancellationTokenSource();

        var token = _workCts.Token;
        ShadowAlert?.Invoke("[Shadow AI] Activada en modo sigiloso - apoyando a las AIs principales");
        _log?.Log(new LogEntry
        {
            Event = "Shadow Helper AI activada para asistencia sigilosa",
            ActionTaken = "Activación Shadow AI",
            User = "Secure AI Shadow"
        });

        Task.Run(() => WorkLoop(token), token);
    }

    public void Deactivate()
    {
        if (!_isActive) return;
        _isActive = false;
        _workCts?.Cancel();
        _workCts?.Dispose();
        _workCts = null;
        _remainingQuota = 0;
        _isBusy = false;

        ShadowAlert?.Invoke("[Shadow AI] Desactivada - tareas completadas");
        _log?.Log(new LogEntry
        {
            Event = "Shadow Helper AI desactivada - cuota de trabajo completada",
            ActionTaken = "Desactivación Shadow AI",
            User = "Secure AI Shadow"
        });
    }

    public void RequestAssist(string taskType, string? target = null)
    {
        if (!_isActive)
        {
            Activate();
            return;
        }

        if (_remainingQuota <= 0) return;

        ShadowAlert?.Invoke($"[Shadow AI] Asistiendo en tarea: {taskType}");

        switch (taskType.ToLowerInvariant())
        {
            case "deepscan" when !string.IsNullOrEmpty(target):
                _ = Task.Run(() => DeepScanTarget(target));
                break;
            case "memory":
                _ = Task.Run(() => AnalyzeMemory());
                break;
            case "registry":
                _ = Task.Run(() => AnalyzeRegistry());
                break;
            case "network":
                _ = Task.Run(() => DeepNetworkCheck());
                break;
            case "alldrives":
                _ = Task.Run(() => ScanAllDrives());
                break;
        }
    }

    private async Task WorkLoop(CancellationToken ct)
    {
        try
        {
            _isBusy = true;
            StatusChanged?.Invoke("[Shadow AI] Ejecutando análisis sigiloso del sistema...");

            await AnalyzeMemory();
            if (ct.IsCancellationRequested || _remainingQuota <= 0) return;

            await AnalyzeRegistry();
            if (ct.IsCancellationRequested || _remainingQuota <= 0) return;

            await MonitorSuspiciousLocations();
            if (ct.IsCancellationRequested || _remainingQuota <= 0) return;

            await DeepNetworkCheck();

            StatusChanged?.Invoke("[Shadow AI] Análisis sigiloso completado - entrando en modo reposo");
            _isBusy = false;

            if (!ct.IsCancellationRequested)
            {
                await Task.Delay(5000, ct);
                Deactivate();
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            ShadowAlert?.Invoke($"[Shadow AI] Error interno: {ex.Message}");
            _isBusy = false;
            Deactivate();
        }
    }

    private Task AnalyzeMemory()
    {
        if (_remainingQuota <= 0) return Task.CompletedTask;

        try
        {
            ShadowAlert?.Invoke("[Shadow AI] Analizando procesos en memoria...");

            var suspiciousModules = new Dictionary<string, int>();
            var processCount = 0;

            foreach (var proc in Process.GetProcesses())
            {
                if (processCount++ > 500) break;

                try
                {
                    var name = proc.ProcessName.ToLowerInvariant();
                    if (string.IsNullOrEmpty(name)) continue;

                    foreach (ProcessModule module in proc.Modules)
                    {
                        var modName = module.ModuleName?.ToLowerInvariant() ?? "";
                        if (string.IsNullOrEmpty(modName) || modName.Length < 4) continue;

                        if (!suspiciousModules.ContainsKey(modName))
                            suspiciousModules[modName] = 0;
                        suspiciousModules[modName]++;

                        if (suspiciousModules[modName] > 3)
                        {
                            var key = $"mod_{modName}";
                            if (!_scanCache.ContainsKey(key))
                            {
                                _scanCache[key] = DateTime.Now;
                                var msg = $"[Shadow AI] Módulo inyectado en múltiples procesos: {modName} ({suspiciousModules[modName]} procesos)";
                                ShadowAlert?.Invoke(msg);
                                ThreatFound?.Invoke(msg, ThreatLevel.Medium);
                            }
                        }
                    }

                    var memSize = 0L;
                    try { memSize = proc.WorkingSet64; } catch { }
                    if (memSize > 500 * 1024 * 1024 && !name.Contains("secureia") && !name.Contains("svchost"))
                    {
                        var key = $"mem_{name}_{proc.Id}";
                        if (!_scanCache.ContainsKey(key))
                        {
                            _scanCache[key] = DateTime.Now;
                            var msg = $"[Shadow AI] Proceso con uso anormal de memoria: {name} ({memSize / (1024 * 1024)} MB)";
                            ShadowAlert?.Invoke(msg);
                            ThreatFound?.Invoke(msg, ThreatLevel.Low);
                        }
                    }
                }
                catch { }
            }

            _remainingQuota--;
        }
        catch { }

        return Task.CompletedTask;
    }

    private Task AnalyzeRegistry()
    {
        if (_remainingQuota <= 0) return Task.CompletedTask;

        try
        {
            ShadowAlert?.Invoke("[Shadow AI] Escaneando entradas de registro sospechosas...");

            var runKeys = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
            };

            foreach (var keyPath in runKeys)
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath);
                if (key == null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    var val = key.GetValue(valueName)?.ToString() ?? "";
                    if (string.IsNullOrEmpty(val)) continue;

                    var lower = val.ToLowerInvariant();
                    var suspiciousPatterns = new[]
                    {
                        "powershell -enc", "powershell -e ", "frombase64string",
                        "downloadstring", "downloadfile", "invoke-expression",
                        "iex(", "start-process -windowstyle hidden", "mshta",
                        "wscript", "cscript", "rundll32", "regsvr32",
                        "bitsadmin", "certutil", "msiexec /q", "msiexec /quiet"
                    };

                    foreach (var pattern in suspiciousPatterns)
                    {
                        if (lower.Contains(pattern))
                        {
                            var cacheKey = $"reg_{keyPath}_{valueName}_{pattern.GetHashCode()}";
                            if (!_scanCache.ContainsKey(cacheKey))
                            {
                                _scanCache[cacheKey] = DateTime.Now;
                                var msg = $"[Shadow AI] Persistencia sigilosa en registro: {valueName} -> {val}";
                                ShadowAlert?.Invoke(msg);
                                ThreatFound?.Invoke(msg, ThreatLevel.High);
                            }
                        }
                    }
                }
            }

            _remainingQuota--;
        }
        catch { }

        return Task.CompletedTask;
    }

    private Task MonitorSuspiciousLocations()
    {
        if (_remainingQuota <= 0) return Task.CompletedTask;

        try
        {
            ShadowAlert?.Invoke("[Shadow AI] Examinando ubicaciones vulnerables del sistema...");

            var sensitivePaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "Roaming"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
            };

            foreach (var basePath in sensitivePaths)
            {
                if (!Directory.Exists(basePath)) continue;
                if (_scannedDirs.Contains(basePath)) continue;

                try
                {
                    int filesChecked = 0;
                    foreach (var file in Directory.EnumerateFiles(basePath, "*.*", SearchOption.TopDirectoryOnly))
                    {
                        if (filesChecked++ > 30) break;
                        if (_remainingQuota <= 0) break;

                        try
                        {
                            var fi = new FileInfo(file);
                            if (fi.Length < 1024 || fi.Length > 50 * 1024 * 1024) continue;

                            var ext = Path.GetExtension(file).ToLowerInvariant();
                            if (ext != ".exe" && ext != ".dll" && ext != ".scr" &&
                                ext != ".ps1" && ext != ".vbs" && ext != ".bat" &&
                                ext != ".cmd" && ext != ".js") continue;

                            using var sha256 = SHA256.Create();
                            using var stream = File.OpenRead(file);
                            var hash = sha256.ComputeHash(stream);
                            var hashStr = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();

                            if (_threatDb != null && _threatDb.IsThreatByIoC(hashStr))
                            {
                                var msg = $"[Shadow AI] Archivo malicioso conocido detectado: {fi.Name} (SHA256: {hashStr[..16]}...)";
                                ShadowAlert?.Invoke(msg);
                                ThreatFound?.Invoke(msg, ThreatLevel.Critical);
                                _remainingQuota--;
                            }

                            if (_defService != null && _defService.IsKnownThreat(file))
                            {
                                var msg = $"[Shadow AI] Coincidencia con base de amenazas: {fi.Name}";
                                ShadowAlert?.Invoke(msg);
                                ThreatFound?.Invoke(msg, ThreatLevel.High);
                                _remainingQuota--;
                            }
                        }
                        catch { }
                    }

                    _scannedDirs.Add(basePath);
                }
                catch { }
            }

            _remainingQuota--;
        }
        catch { }

        return Task.CompletedTask;
    }

    private Task DeepNetworkCheck()
    {
        if (_remainingQuota <= 0) return Task.CompletedTask;

        try
        {
            ShadowAlert?.Invoke("[Shadow AI] Verificando conexiones de red encubiertas...");

            var properties = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties();
            var tcpConnections = properties.GetActiveTcpConnections();

            var suspiciousPorts = new HashSet<int> { 4444, 5555, 6666, 7777, 8888, 9999, 1337, 4443, 4445, 9001, 9002, 31337, 12345, 12346, 20034, 40421, 40422, 54321 };

            foreach (var conn in tcpConnections)
            {
                if (conn.State != System.Net.NetworkInformation.TcpState.Established) continue;

                var localPort = conn.LocalEndPoint.Port;
                var remotePort = conn.RemoteEndPoint.Port;
                var remoteIp = conn.RemoteEndPoint.Address.ToString();

                if (suspiciousPorts.Contains(localPort) || suspiciousPorts.Contains(remotePort))
                {
                    var key = $"shadow_net_{localPort}_{remotePort}_{remoteIp}";
                    if (!_scanCache.ContainsKey(key))
                    {
                        _scanCache[key] = DateTime.Now;
                        var msg = $"[Shadow AI] Conexión sigilosa en puerto anómalo: {conn.LocalEndPoint} -> {conn.RemoteEndPoint}";
                        ShadowAlert?.Invoke(msg);
                        ThreatFound?.Invoke(msg, ThreatLevel.High);
                        _remainingQuota--;
                    }
                }

                if (_threatDb != null && !IsLocalAddress(conn.RemoteEndPoint.Address))
                {
                    if (_threatDb.IsKnownC2Ip(remoteIp))
                    {
                        var key = $"shadow_c2_{remoteIp}";
                        if (!_scanCache.ContainsKey(key))
                        {
                            _scanCache[key] = DateTime.Now;
                            var msg = $"[Shadow AI] C2/Botnet detectado en segundo plano: {remoteIp}:{remotePort}";
                            ShadowAlert?.Invoke(msg);
                            ThreatFound?.Invoke(msg, ThreatLevel.Critical);
                            _remainingQuota--;
                        }
                    }
                }
            }

            _remainingQuota--;
        }
        catch { }

        return Task.CompletedTask;
    }

    private Task DeepScanTarget(string targetPath)
    {
        if (_remainingQuota <= 0 || !File.Exists(targetPath)) return Task.CompletedTask;

        try
        {
            ShadowAlert?.Invoke($"[Shadow AI] Analizando objetivo: {targetPath}");

            if (_deepAnalyzer != null)
            {
                var results = _deepAnalyzer.AnalyzeDeep(targetPath);
                foreach (var result in results)
                {
                    if (result.Level >= ThreatLevel.Medium)
                    {
                        ScanResultFound?.Invoke(result);
                        ThreatFound?.Invoke($"[Shadow AI] Amenaza confirmada: {result.ThreatName}", result.Level);
                    }
                }
            }

            _remainingQuota--;
        }
        catch { }

        return Task.CompletedTask;
    }

    private Task ScanAllDrives()
    {
        if (_remainingQuota <= 0) return Task.CompletedTask;

        try
        {
            ShadowAlert?.Invoke("[Shadow AI] Explorando unidades en busca de amenazas ocultas...");

            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                if (drive.DriveType == DriveType.CDRom) continue;

                try
                {
                    int checkedFiles = 0;
                    foreach (var file in Directory.EnumerateFiles(drive.RootDirectory.FullName, "*.*", SearchOption.TopDirectoryOnly))
                    {
                        if (checkedFiles++ > 20) break;
                        if (_remainingQuota <= 0) break;

                        var ext = Path.GetExtension(file).ToLowerInvariant();
                        if (ext == ".exe" || ext == ".scr" || ext == ".ps1" || ext == ".vbs")
                        {
                            var fi = new FileInfo(file);
                            if (fi.Length < 1024 * 1024)
                            {
                                var key = $"drive_{file}_{fi.Length}";
                                if (!_scanCache.ContainsKey(key))
                                {
                                    _scanCache[key] = DateTime.Now;
                                    var msg = $"[Shadow AI] Ejecutable en raíz de {drive.Name}: {fi.Name}";
                                    ShadowAlert?.Invoke(msg);
                                    ThreatFound?.Invoke(msg, ThreatLevel.Low);
                                }
                            }
                        }
                    }
                }
                catch { }
            }

            _remainingQuota--;
        }
        catch { }

        return Task.CompletedTask;
    }

    private static bool IsLocalAddress(System.Net.IPAddress address)
    {
        if (System.Net.IPAddress.IsLoopback(address)) return true;
        var bytes = address.GetAddressBytes();
        if (bytes[0] == 10) return true;
        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
        if (bytes[0] == 192 && bytes[1] == 168) return true;
        if (bytes[0] == 169 && bytes[1] == 254) return true;
        return false;
    }

    public void Dispose()
    {
        _workCts?.Cancel();
        _workCts?.Dispose();
        _workCts = null;
    }
}
