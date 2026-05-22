using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using Secureia.Models;

namespace Secureia.Services;

// Main AI - Comandante principal que orquesta las AIs expertas (ExpertMalwareAI, ExpertNetworkAI, ShadowHelperAI)
// y coordina la defensa del sistema (DefenseShieldAI, UsbScanner)
public class BackgroundMonitor : IDisposable
{
    private CancellationTokenSource? _cts;
    private readonly TtsService? _tts;
    private readonly LogService? _log;
    private readonly PlusActivationService? _plus;
    private readonly ExpertMalwareAI? _expertMalware;
    private readonly ExpertNetworkAI? _expertNetwork;
    private readonly ShadowHelperAI? _shadowHelper;
    private readonly UsbScanner? _usbScanner;
    private readonly DefenseShieldAI? _shield;
    private readonly ScanEngine? _scanEngine;
    private readonly CleanupService? _cleanupService;
    private readonly HashSet<int> _knownPids = new();
    private readonly HashSet<int> _knownPorts = new();
    private readonly HashSet<int> _reportedInstallerPids = new();
    private readonly Dictionary<string, DateTime> _fileChangeTracker = new();
    private long _lastTotalConnections;
    private DateTime _lastConnectionCheck = DateTime.UtcNow;
    private int _deauthAlertCooldown;
    private FileSystemWatcher? _fileWatcher;
    private DeepAnalyzer? _deepAnalyzer;
    private DefinitionService? _defService;
    private ThreatDatabase? _threatDb;
    private bool _isShuttingDown;

    private readonly Dictionary<string, int> _ransomwareFileCount = new();

    public event Action<string>? Alert;
    public event Action<string, int>? ShieldStatusChanged;
    public event Action<int, int>? UsbScanProgress;
    public event Action<string>? UsbScanStatus;
    public bool IsShieldActive => _shield?.IsShieldActive ?? false;
    public int ShieldLevel => _shield?.AggressionLevel ?? 0;

    public BackgroundMonitor(TtsService? tts = null, LogService? log = null,
                             DefinitionService? defService = null, ThreatDatabase? threatDb = null,
                             PlusActivationService? plus = null,
                             ExpertMalwareAI? expertMalware = null,
                             ExpertNetworkAI? expertNetwork = null,
                             UsbScanner? usbScanner = null,
                             DefenseShieldAI? shield = null,
                             ScanEngine? scanEngine = null,
                             ShadowHelperAI? shadowHelper = null,
                             CleanupService? cleanupService = null)
    {
        _tts = tts;
        _log = log;
        _defService = defService;
        _threatDb = threatDb;
        _plus = plus;
        _expertMalware = expertMalware;
        _expertNetwork = expertNetwork;
        _shadowHelper = shadowHelper;
        _usbScanner = usbScanner;
        _shield = shield;
        _scanEngine = scanEngine;
        _cleanupService = cleanupService;
    }

    public void Start()
    {
        if (_cts != null) return;
        _cts = new CancellationTokenSource();

        foreach (var proc in Process.GetProcesses())
            _knownPids.Add(proc.Id);

        try
        {
            var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
            foreach (var ep in listeners)
                _knownPorts.Add(ep.Port);
        }
        catch { }

        _deepAnalyzer = new DeepAnalyzer(_defService, _threatDb);
        StartFileWatcher();

        if (_shield != null)
        {
            _shield.EmergencyAlert += msg => Alert?.Invoke($"[ESCUDO] {msg}");
            _shield.ShieldStatusChanged += (msg, lvl) => ShieldStatusChanged?.Invoke(msg, lvl);
        }

        if (_shadowHelper != null)
        {
            _shadowHelper.ShadowAlert += msg => Alert?.Invoke(msg);
            _shadowHelper.ThreatFound += (msg, level) =>
            {
                Alert?.Invoke(msg);
                if (level >= ThreatLevel.High)
                    _tts?.Speak("Shadow AI ha detectado una amenaza encubierta.");
            };
            _shadowHelper.StatusChanged += msg => Alert?.Invoke(msg);
        }

        if (_expertNetwork != null)
        {
            _expertNetwork.NetworkAlert += entry =>
            {
                Alert?.Invoke($"[Red] {entry.Event}");

                if (entry.Level == ThreatLevel.Critical || entry.Level == ThreatLevel.High)
                {
                    // NOTA: NO bloquear internet ni activar escudo ofensivo.
                    // En lugar de eso, activar Shadow Helper AI para que apoye
                    // en el análisis y mitigación de la amenaza de red.
                    _shadowHelper?.Activate();
                    _shadowHelper?.RequestAssist("network");
                    if (entry.Level == ThreatLevel.Critical)
                        _shadowHelper?.RequestAssist("deepscan");
                }
            };
        }

        if (_usbScanner != null)
        {
            _usbScanner.ScanProgress += (p, t) => UsbScanProgress?.Invoke(p, t);
            _usbScanner.ScanStatus += s => UsbScanStatus?.Invoke(s);
        }

        Task.Run(() => MonitorLoop(_cts.Token));
    }

    public void Stop()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
        _fileWatcher?.Dispose();
        _fileWatcher = null;
    }

    private void StartFileWatcher()
    {
        try
        {
            _fileWatcher = new FileSystemWatcher
            {
                Path = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                IncludeSubdirectories = false,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite,
                InternalBufferSize = 65536
            };

            _fileWatcher.Created += async (s, e) =>
            {
                try
                {
                    if (File.Exists(e.FullPath))
                    {
                        var fi = new FileInfo(e.FullPath);
                        if (fi.Length > 1024 * 1024) return;

                        await Task.Delay(1000);
                        if (_deepAnalyzer != null)
                        {
                            var results = _deepAnalyzer.AnalyzeDeep(e.FullPath);
                            foreach (var result in results)
                            {
                                Alert?.Invoke($"[Análisis en tiempo real] {result.ThreatName}: {e.Name}");
                                _log?.Log(new Models.LogEntry
                                {
                                    Event = $"Amenaza detectada en tiempo real: {result.ThreatName}",
                                    FilePath = e.FullPath,
                                    ActionTaken = "Alerta automática",
                                    User = Environment.UserName
                                });
                            }
                        }
                    }
                }
                catch { }
            };

            _fileWatcher.EnableRaisingEvents = true;
        }
        catch { }
    }

    private async Task MonitorLoop(CancellationToken ct)
    {
        int cycleCount = 0;
        bool isPlus = _plus?.IsPlusActive ?? false;
        int shadowActivationCycle = 0;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                isPlus = _plus?.IsPlusActive ?? false;

                if (isPlus && _expertMalware != null && _expertNetwork != null)
                {
                    _expertMalware.ScanRunningProcesses();
                    _expertNetwork.AnalyzeOpenPorts();
                    _expertNetwork.DetectBackdoors();
                    _expertNetwork.DetectReverseShells();
                    _usbScanner?.PollForNewDrives();

                    if (_shield != null && _shield.IsShieldActive)
                        _shield.MonitorThreats();

                    if (cycleCount % 3 == 0)
                    {
                        _expertMalware.DetectRansomware();
                        _expertMalware.DetectRootkits();
                        _expertMalware.DetectPersistenceMechanisms();
                        _expertNetwork.DetectDoSAttack();
                        _expertNetwork.DetectUnauthorizedRemoteConnections();
                        _expertNetwork.DetectWiFiDeauth();
                        _expertNetwork.DetectNetworkScan();
                        _expertNetwork.DetectDnsTunneling();

                        AssessOverallSecurity();
                    }

                    CheckInstallers();

                    shadowActivationCycle++;
                    if (shadowActivationCycle >= 12 && _shadowHelper != null && !_shadowHelper.IsActive)
                    {
                        shadowActivationCycle = 0;
                        _shadowHelper.Activate();
                        Alert?.Invoke("[Main AI] Shadow AI activada para patrullaje sigiloso de rutina");
                    }
                }
                else
                {
                    CheckNewProcesses();
                    CheckOpenPorts();
                    CheckInstallers();

                    if (cycleCount % 6 == 0)
                    {
                        CheckRansomwareBehavior();
                        CheckNetworkAnomalies();
                        CheckWiFiDeauth();
                        CheckRootkitIndicators();
                        CheckAdvancedThreats();
                    }

                    shadowActivationCycle++;
                    if (shadowActivationCycle >= 12 && _shadowHelper != null && !_shadowHelper.IsActive)
                    {
                        shadowActivationCycle = 0;
                        _shadowHelper.Activate();
                        Alert?.Invoke("[Main AI] Shadow AI activada para patrullaje sigiloso de rutina");
                    }
                }

                cycleCount++;
            }
            catch { }

            await Task.Delay(5000, ct);
        }
    }

    private void AssessOverallSecurity()
    {
        try
        {
            var properties = IPGlobalProperties.GetIPGlobalProperties();
            var listeners = properties.GetActiveTcpListeners();
            var connections = properties.GetActiveTcpConnections();

            // NUNCA bloquear internet o activar escudo ofensivo por tráfico de red.
            // En lugar de eso, activar Shadow Helper AI para que asista en el análisis
            // y mitigación de amenazas sin interrumpir la conectividad del usuario.
            if (listeners.Length > 250 && connections.Length > 800)
            {
                var msg = "Tráfico de red anormalmente alto - activando Shadow AI para asistencia";
                Alert?.Invoke($"[Main AI] {msg}");
                _shadowHelper?.Activate();
                _shadowHelper?.RequestAssist("network");
                _log?.Log(new LogEntry
                {
                    Event = msg,
                    ActionTaken = "Shadow AI asistente activada (reemplaza bloqueo de red)",
                    User = "Secure AI Main"
                });
            }

            // Ransomware - única excepción donde el escudo puede actuar
            // porque no bloquea internet, sino que protege archivos locales.
            if (_ransomwareFileCount.Values.Any(v => v >= 10))
            {
                var msg = "Actividad de ransomware confirmada - activando Shadow AI y escudo local";
                Alert?.Invoke($"[Main AI] {msg}");
                _shadowHelper?.Activate();
                _shadowHelper?.RequestAssist("deepscan");
                _shield?.ActivateShield(1, "Actividad de ransomware confirmada - protección local");
                _log?.Log(new LogEntry
                {
                    Event = msg,
                    ActionTaken = "Shadow AI + Escudo local activado por ransomware",
                    User = "Secure AI Main"
                });
            }
        }
        catch { }
    }

    public void DeclareEmergency(string reason, ThreatLevel level)
    {
        _tts?.SpeakCriticalThreat();
        Alert?.Invoke($"[EMERGENCIA] {reason}");

        // Nunca bloquear internet - activar Shadow Helper AI para asistencia
        _shadowHelper?.Activate();
        _shadowHelper?.RequestAssist("deepscan");
        _shadowHelper?.RequestAssist("memory");

        _log?.Log(new LogEntry
        {
            Event = $"EMERGENCIA: {reason} - Shadow Helper AI activada para asistencia",
            ActionTaken = $"Alerta de emergencia nivel {level} - Shadow AI desplegada",
            User = Environment.UserName,
            Level = level
        });
    }

    private void CheckInstallers()
    {
        var installerProcesses = Process.GetProcessesByName("msiexec")
            .Concat(Process.GetProcessesByName("installer"))
            .Concat(Process.GetProcessesByName("setup"));

        foreach (var proc in installerProcesses)
        {
            if (_reportedInstallerPids.Contains(proc.Id)) continue;
            _reportedInstallerPids.Add(proc.Id);

            try
            {
                var path = proc.MainModule?.FileName ?? "desconocido";
                var msg = $"Instalación detectada: {proc.ProcessName} (PID: {proc.Id}) - {path}";
                Alert?.Invoke(msg);
                _log?.Log(new Models.LogEntry
                {
                    Event = $"Instalación detectada: {path}",
                    FilePath = path,
                    ActionTaken = "Monitoreo",
                    User = Environment.UserName
                });
                _tts?.Speak("Se detectó una instalación en el sistema.");
            }
            catch { }
        }
    }

    private void CheckNewProcesses()
    {
        var current = new HashSet<int>(Process.GetProcesses().Select(p => p.Id));

        foreach (var pid in current)
        {
            if (_knownPids.Contains(pid)) continue;
            _knownPids.Add(pid);

            try
            {
                var proc = Process.GetProcessById(pid);
                var name = proc.ProcessName.ToLower();

                var ransomwareProcs = new[] { "xmrig", "minerd", "ccminer", "ethminer" };
                var dosTools = new[] { "hping", "slowloris", "goldeneye", "LOIC", "HOIC" };
                var deauthTools = new[] { "aireplay", "mdk3", "mdk4", "airgeddon", "fluxion" };

                var matchedRansomware = ransomwareProcs.FirstOrDefault(s => name == s || name.StartsWith(s));
                if (matchedRansomware != null)
                {
                    var msg = $"[Ransomware/ Miner] Proceso detectado: {name} (PID: {pid})";
                    Alert?.Invoke(msg);
                    _log?.Log(new Models.LogEntry
                    {
                        Event = $"Proceso minero: {name}",
                        ActionTaken = "Monitoreo",
                        User = Environment.UserName
                    });
                    _tts?.Speak("Se detectó un proceso de minero en el sistema.");
                    continue;
                }

                var matchedDoS = dosTools.FirstOrDefault(s => name == s || name.StartsWith(s));
                if (matchedDoS != null)
                {
                    var msg = $"[DoS/DDoS] Herramienta detectada: {name} (PID: {pid})";
                    Alert?.Invoke(msg);
                    _log?.Log(new Models.LogEntry
                    {
                        Event = $"Herramienta DoS: {name}",
                        ActionTaken = "Monitoreo",
                        User = Environment.UserName
                    });
                    _tts?.Speak("Se detectó una herramienta de ataque de red.");
                    continue;
                }

                var matchedDeauth = deauthTools.FirstOrDefault(s => name == s || name.StartsWith(s));
                if (matchedDeauth != null)
                {
                    var msg = $"[Deauth] Herramienta detectada: {name} (PID: {pid})";
                    Alert?.Invoke(msg);
                    _log?.Log(new Models.LogEntry
                    {
                        Event = $"Herramienta de desautenticación: {name}",
                        ActionTaken = "Monitoreo",
                        User = Environment.UserName
                    });
                    _tts?.Speak("Se detectó una herramienta de desautenticación Wi-Fi.");
                    continue;
                }
            }
            catch { }
        }
    }

    private void CheckOpenPorts()
    {
        try
        {
            var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
            foreach (var ep in listeners)
            {
                if (_knownPorts.Contains(ep.Port)) continue;
                _knownPorts.Add(ep.Port);

                if (ep.Port > 49152) continue;

                var msg = $"Nuevo puerto abierto: {ep.Address}:{ep.Port}";
                Alert?.Invoke(msg);
                _log?.Log(new Models.LogEntry
                {
                    Event = "Puerto abierto detectado",
                    FilePath = ep.ToString(),
                    ActionTaken = "Monitoreo",
                    User = Environment.UserName
                });
            }
        }
        catch { }
    }

    private void CheckRansomwareBehavior()
    {
        try
        {
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            var downloads = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

            var sensitiveDirs = new[] { desktop, docs, downloads };
            var currentRansomwareFiles = new Dictionary<string, int>();
            var hasRansomNote = false;

            var cryptoExtensions = _threatDb?.RansomwareExtensions ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".encrypted", ".locked", ".crypt", ".locky", ".wncry", ".onion",
                ".crinf", ".djvu", ".lockbit", ".blackcat", ".revil", ".hive",
                ".conti", ".akira", ".play", ".royal", ".quantum"
            };

            foreach (var dir in sensitiveDirs)
            {
                if (!Directory.Exists(dir)) continue;
                foreach (var file in Directory.EnumerateFiles(dir, "*.*", SearchOption.TopDirectoryOnly))
                {
                    if (Path.GetExtension(file)?.Equals(".lnk", StringComparison.OrdinalIgnoreCase) == true)
                        continue;

                    var ext = Path.GetExtension(file)?.ToLowerInvariant() ?? "";

                    if (cryptoExtensions.Contains(ext))
                    {
                        var dirKey = dir.ToLowerInvariant();
                        if (!currentRansomwareFiles.ContainsKey(dirKey))
                            currentRansomwareFiles[dirKey] = 0;
                        currentRansomwareFiles[dirKey]++;

                        var changeKey = $"ransom_{file.ToLowerInvariant()}";
                        if (!_fileChangeTracker.ContainsKey(changeKey))
                            _fileChangeTracker[changeKey] = DateTime.Now;
                    }

                    var fileName = Path.GetFileNameWithoutExtension(file)?.ToLowerInvariant() ?? "";
                    if (fileName.Contains("decrypt") || fileName.Contains("readme") ||
                        fileName.Contains("ransom") || fileName.Contains("recover"))
                    {
                        hasRansomNote = true;
                        var noteKey = $"note_{file.ToLowerInvariant()}";
                        if (!_fileChangeTracker.ContainsKey(noteKey))
                        {
                            _fileChangeTracker[noteKey] = DateTime.Now;
                        }
                    }
                }
            }

            foreach (var kvp in currentRansomwareFiles)
            {
                var existingCount = _ransomwareFileCount.GetValueOrDefault(kvp.Key, 0);
                if (kvp.Value > existingCount)
                {
                    var newCount = kvp.Value - existingCount;
                    _ransomwareFileCount[kvp.Key] = kvp.Value;

                    if (kvp.Value >= 5 && hasRansomNote)
                    {
                        var msg = $"[Ransomware] {kvp.Value} archivos cifrados detectados en {kvp.Key} con nota de rescate";
                        Alert?.Invoke(msg);
                        _log?.Log(new Models.LogEntry
                        {
                            Event = $"Posible ataque de ransomware: {kvp.Value} archivos cifrados",
                            FilePath = kvp.Key,
                            ActionTaken = "Alerta crítica",
                            User = Environment.UserName
                        });
                        _tts?.Speak("¡Alerta! Posible ataque de ransomware detectado en el sistema.");
                        hasRansomNote = false;
                    }
                    else if (kvp.Value >= 10)
                    {
                        var msg = $"[Ransomware] {kvp.Value} archivos cifrados en {kvp.Key} - posible ataque masivo";
                        Alert?.Invoke(msg);
                        _log?.Log(new Models.LogEntry
                        {
                            Event = $"Múltiples archivos cifrados: {kvp.Value}",
                            FilePath = kvp.Key,
                            ActionTaken = "Alerta",
                            User = Environment.UserName
                        });
                        _tts?.Speak("Se detectaron múltiples archivos cifrados en el sistema.");
                    }
                }
            }
        }
        catch { }
    }

    private void CheckNetworkAnomalies()
    {
        try
        {
            var properties = IPGlobalProperties.GetIPGlobalProperties();
            var tcpConnections = properties.GetActiveTcpConnections();
            var currentTotal = tcpConnections.Length;

            if (_lastTotalConnections > 0)
            {
                var now = DateTime.UtcNow;
                var elapsed = (now - _lastConnectionCheck).TotalSeconds;
                if (elapsed > 0)
                {
                    var rate = (currentTotal - _lastTotalConnections) / elapsed;

                    if (rate > 100)
                    {
                        var msg = $"[DoS/DDoS] Alta tasa de conexiones: {rate:F0} conexiones/segundo";
                        Alert?.Invoke(msg);
                        _log?.Log(new Models.LogEntry
                        {
                            Event = $"Posible ataque DoS/DDoS: {rate:F0} conexiones/s",
                            FilePath = $"{currentTotal} conexiones activas",
                            ActionTaken = "Alerta de red",
                            User = Environment.UserName
                        });
                        _tts?.Speak("Se detectó una tasa anormal de conexiones de red.");
                    }
                }
            }

            _lastTotalConnections = currentTotal;
            _lastConnectionCheck = DateTime.UtcNow;

            var listeners = properties.GetActiveTcpListeners();
            if (listeners.Length > 100)
            {
                var msg = $"[Red] Número anormal de puertos en escucha: {listeners.Length}";
                Alert?.Invoke(msg);
            }
        }
        catch { }
    }

    private void CheckWiFiDeauth()
    {
        try
        {
            if (_deauthAlertCooldown > 0)
            {
                _deauthAlertCooldown--;
                return;
            }

            var psi = new ProcessStartInfo("netsh", "wlan show interfaces")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);

            var isDisconnected = output.Contains(" desconectado", StringComparison.OrdinalIgnoreCase) ||
                                 output.Contains(" disconnected", StringComparison.OrdinalIgnoreCase) ||
                                 output.Contains("no está conectado", StringComparison.OrdinalIgnoreCase);

            var isConnected = output.Contains("conectado", StringComparison.OrdinalIgnoreCase) ||
                              output.Contains("connected", StringComparison.OrdinalIgnoreCase);

            if (isConnected)
            {
                _deauthAlertCooldown = 0;
            }
            else if (isDisconnected && !isConnected)
            {
                Thread.Sleep(2000);
                using var proc2 = Process.Start(new ProcessStartInfo("netsh", "wlan show interfaces")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                });
                if (proc2 != null)
                {
                    var checkAgain = proc2.StandardOutput.ReadToEnd();
                    proc2.WaitForExit(3000);
                    var stillDisconnected = checkAgain.Contains(" desconectado") ||
                                            checkAgain.Contains("no está conectado");
                    if (stillDisconnected)
                    {
                        var msg = "[Deauth] Posible ataque de desautenticación Wi-Fi: conexión perdida repentinamente";
                        Alert?.Invoke(msg);
                        _log?.Log(new Models.LogEntry
                        {
                            Event = "Posible ataque de desautenticación Wi-Fi",
                            FilePath = "Interfaz Wi-Fi",
                            ActionTaken = "Alerta de red inalámbrica",
                            User = Environment.UserName
                        });
                        _tts?.Speak("Alerta. Posible ataque de desautenticación Wi-Fi detectado.");
                        _deauthAlertCooldown = 12;
                    }
                }
            }
        }
        catch { }
    }

    private void CheckRootkitIndicators()
    {
        try
        {
            var systemDrivers = Path.Combine(Environment.SystemDirectory, "drivers");
            if (!Directory.Exists(systemDrivers)) return;

            var knownRootkitDrivers = _threatDb?.RootkitDriverNames ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "capcom.sys", "gdrv.sys", "kprocesshacker.sys",
                "pchunter.sys", "powerkiller.sys", "winring0x64.sys", "winring0.sys"
            };

            foreach (var driverFile in Directory.EnumerateFiles(systemDrivers, "*.sys", SearchOption.TopDirectoryOnly))
            {
                var name = Path.GetFileName(driverFile).ToLowerInvariant();
                if (knownRootkitDrivers.Contains(name))
                {
                    var key = $"driver_{name}";
                    if (!_fileChangeTracker.ContainsKey(key))
                    {
                        _fileChangeTracker[key] = DateTime.Now;
                        var msg = $"[Rootkit] Controlador sospechoso detectado: {name}";
                        Alert?.Invoke(msg);
                        _log?.Log(new Models.LogEntry
                        {
                            Event = $"Controlador rootkit detectado: {name}",
                            FilePath = driverFile,
                            ActionTaken = "Alerta de rootkit",
                            User = Environment.UserName
                        });
                        _tts?.Speak("Se detectó un controlador de rootkit en el sistema.");
                    }
                }
            }
        }
        catch { }
    }

    private void CheckAdvancedThreats()
    {
        try
        {
            // Persistencia sospechosa en RUN registry
            var autoStartKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
            if (autoStartKey != null)
            {
                var entries = autoStartKey.GetValueNames();
                foreach (var entry in entries)
                {
                    var val = autoStartKey.GetValue(entry)?.ToString() ?? "";
                    var lower = val.ToLowerInvariant();
                    if (lower.Contains("temp") && !lower.Contains("secureia"))
                    {
                        var key = $"persist_{entry}";
                        if (!_fileChangeTracker.ContainsKey(key))
                        {
                            _fileChangeTracker[key] = DateTime.Now;
                            var msg = $"[Avanzado] Persistencia sospechosa: '{entry}' desde {val}";
                            Alert?.Invoke(msg);
                            _log?.Log(new Models.LogEntry
                            {
                                Event = $"Persistencia sospechosa: {entry} -> {val}",
                                FilePath = val,
                                ActionTaken = "Alerta avanzada",
                                User = Environment.UserName
                            });
                            _tts?.Speak("Se detectó un mecanismo de persistencia sospechoso.");
                            _shadowHelper?.Activate();
                            _shadowHelper?.RequestAssist("registry");
                        }
                    }
                }
            }

            // Verificar conexiones activas contra base de IoCs (C2, botnets)
            if (_threatDb != null)
            {
                try
                {
                    var properties = IPGlobalProperties.GetIPGlobalProperties();
                    var tcpConnections = properties.GetActiveTcpConnections();

                    foreach (var conn in tcpConnections)
                    {
                        if (conn.State != TcpState.Established) continue;
                        if (IsLocalAddress(conn.RemoteEndPoint.Address)) continue;

                        var remoteIp = conn.RemoteEndPoint.Address.ToString();

                        if (_threatDb.IsKnownC2Ip(remoteIp))
                        {
                            var key = $"c2_{remoteIp}";
                            if (!_fileChangeTracker.ContainsKey(key))
                            {
                                _fileChangeTracker[key] = DateTime.Now;
                                var msg = $"[C2/Botnet] Conexión a servidor C2 conocido: {conn.LocalEndPoint} -> {conn.RemoteEndPoint}";
                                Alert?.Invoke(msg);
                                _log?.Log(new Models.LogEntry
                                {
                                    Event = $"Conexión C2 detectada: {remoteIp}",
                                    FilePath = conn.RemoteEndPoint.ToString(),
                                    ActionTaken = "Alerta IoC",
                                    User = Environment.UserName
                                });
                                _tts?.Speak("Se detectó conexión a un servidor de comando y control.");
                                _shadowHelper?.Activate();
                                _shadowHelper?.RequestAssist("network");
                            }
                        }
                        else if (_threatDb.IsKnownBotnetIp(remoteIp))
                        {
                            var key = $"bot_{remoteIp}";
                            if (!_fileChangeTracker.ContainsKey(key))
                            {
                                _fileChangeTracker[key] = DateTime.Now;
                                var msg = $"[Botnet] Conexión a botnet conocida: {conn.LocalEndPoint} -> {conn.RemoteEndPoint}";
                                Alert?.Invoke(msg);
                                _shadowHelper?.Activate();
                                _shadowHelper?.RequestAssist("network");
                            }
                        }
                    }
                }
                catch { }

                // Verificar consultas DNS contra dominios maliciosos conocidos
                try
                {
                    var psi = new ProcessStartInfo("powershell.exe",
                        "-NoProfile -Command \"Get-DnsClientCache | Select-Object -ExpandProperty Entry | Select-Object -First 50\"")
                    {
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    using var proc = Process.Start(psi);
                    if (proc != null)
                    {
                        var dnsOutput = proc.StandardOutput.ReadToEnd();
                        proc.WaitForExit(3000);

                        foreach (var entry in dnsOutput.Split('\n'))
                        {
                            var d = entry.Trim().ToLowerInvariant();
                            if (string.IsNullOrEmpty(d) || d.StartsWith('#')) continue;
                            if (_threatDb.IsKnownMalwareDomain(d))
                            {
                                var key = $"dns_ioc_{d}";
                                if (!_fileChangeTracker.ContainsKey(key))
                                {
                                    _fileChangeTracker[key] = DateTime.Now;
                                    var msg = $"[Malware] Dominio malicioso en caché DNS: {d}";
                                    Alert?.Invoke(msg);
                                    _shadowHelper?.Activate();
                                }
                            }
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
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

    public void PrepareForShutdown()
    {
        if (_isShuttingDown) return;
        _isShuttingDown = true;

        try
        {
            Alert?.Invoke("[Main AI] Preparando sistema para apagado - ejecutando limpieza profunda...");
            _log?.Log(new LogEntry
            {
                Event = "Apagado iniciado - Main AI ejecutando limpieza profunda",
                ActionTaken = "Limpieza pre-apagado automática",
                User = Environment.UserName
            });

            _shadowHelper?.Deactivate();

            if (_cleanupService != null)
            {
                var result = _cleanupService.RunCleanupSync();
                _log?.Log(new LogEntry
                {
                    Event = $"Limpieza pre-apagado completada: {result.FormattedFreed} liberados",
                    ActionTaken = "Limpieza automática",
                    User = Environment.UserName
                });
            }
        }
        catch { }
    }

    public void Dispose()
    {
        PrepareForShutdown();
        Stop();
    }
}
