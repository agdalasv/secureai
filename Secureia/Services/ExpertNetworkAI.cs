using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;
using Secureia.Models;

namespace Secureia.Services;

public class ExpertNetworkAI
{
    private readonly TtsService? _tts;
    private readonly LogService? _log;
    private readonly ThreatDatabase? _threatDb;
    private readonly DefenseShieldAI? _shield;
    private readonly ReportService? _reports;
    private readonly HashSet<int> _knownPorts = new();
    private readonly HashSet<string> _knownDevices = new();
    private readonly HashSet<string> _knownRemoteIps = new();
    private readonly Dictionary<string, DateTime> _alertCooldown = new();
    private long _lastTotalConnections;
    private DateTime _lastConnectionCheck = DateTime.UtcNow;
    private int _deauthCooldown;
    private int _scanDetectionCooldown;

    public event Action<LogEntry>? NetworkAlert;

    public ExpertNetworkAI(TtsService? tts = null, LogService? log = null, ThreatDatabase? threatDb = null,
                           DefenseShieldAI? shield = null, ReportService? reports = null)
    {
        _tts = tts;
        _log = log;
        _threatDb = threatDb;
        _shield = shield;
        _reports = reports;

        try
        {
            foreach (var ep in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners())
                _knownPorts.Add(ep.Port);

            var ownIps = Dns.GetHostAddresses(Dns.GetHostName());
            foreach (var ip in ownIps)
                _knownRemoteIps.Add(ip.ToString());
        }
        catch { }
    }

    public void AnalyzeOpenPorts()
    {
        try
        {
            var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();

            foreach (var ep in listeners)
            {
                if (_knownPorts.Contains(ep.Port)) continue;
                _knownPorts.Add(ep.Port);

                if (ep.Port > 49152) continue;

                var serviceName = GetPortServiceName(ep.Port);
                var msg = $"[Red] Puerto sospechoso abierto: {ep.Address}:{ep.Port} ({serviceName})";
                EmitNetworkAlert(msg, GetPortThreatLevel(ep.Port),
                    threatType: "PuertoAbierto",
                    description: $"Se detectó un nuevo puerto abierto ({serviceName}) en {ep.Address}:{ep.Port}. Los puertos abiertos pueden ser explotados por atacantes para acceder al sistema.",
                    dstIp: ep.Address.ToString(), dstPort: ep.Port);
            }

            if (listeners.Length > 50)
            {
                var msg = $"[Red] Número anormal de puertos en escucha: {listeners.Length} (posible backdoor o C2)";
                EmitNetworkAlert(msg, ThreatLevel.High,
                    threatType: "PuertosAnormales",
                    description: $"Se detectaron {listeners.Length} puertos en escucha, lo que es anormal y podría indicar la presencia de una puerta trasera o comunicación C2.");
            }
        }
        catch { }
    }

    public void DetectDoSAttack()
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

                    if (rate > 200)
                    {
                        var msg = $"[DoS/DDoS] Ataque detectado: {rate:F0} conexiones/segundo ({currentTotal} conexiones activas)";
                        EmitNetworkAlert(msg, ThreatLevel.Critical,
                            threatType: "DoS/DDoS",
                            description: $"Ataque de denegación de servicio detectado: {rate:F0} conexiones/segundo con {currentTotal} conexiones activas. Esto puede saturar los recursos del sistema.",
                            dstPort: 0);
                    }
                    else if (rate > 80)
                    {
                        var msg = $"[DoS/DDoS] Tráfico anormal: {rate:F0} conexiones/segundo";
                        EmitNetworkAlert(msg, ThreatLevel.High,
                            threatType: "DoS/DDoS",
                            description: $"Tráfico de red anormalmente alto: {rate:F0} conexiones/segundo. Podría ser un ataque DoS en curso.",
                            dstPort: 0);
                    }

                    var synCount = tcpConnections.Count(c =>
                        c.State == TcpState.SynSent || c.State == TcpState.SynReceived);
                    if (synCount > 50)
                    {
                        var msg = $"[DoS] Posible SYN flood: {synCount} conexiones en SYN";
                        EmitNetworkAlert(msg, ThreatLevel.High,
                            threatType: "DoS/DDoS",
                            description: $"Posible ataque SYN flood: {synCount} conexiones en estado SYN pendiente. Esto podría ser un intento de agotar los recursos del sistema.",
                            dstPort: 0);
                    }
                }
            }

            _lastTotalConnections = currentTotal;
            _lastConnectionCheck = DateTime.UtcNow;
        }
        catch { }
    }

    public void DetectBackdoors()
    {
        try
        {
            var properties = IPGlobalProperties.GetIPGlobalProperties();
            var tcpConnections = properties.GetActiveTcpConnections();

            var backdoorPorts = new HashSet<int> { 31337, 31338, 12345, 12346, 20034, 40421, 40422, 40423, 50505, 50766, 54321, 61746, 61747 };

            foreach (var conn in tcpConnections)
            {
                if (conn.State != TcpState.Established) continue;

                if (backdoorPorts.Contains(conn.LocalEndPoint.Port))
                {
                    var msg = $"[Backdoor] Conexión establecida en puerto conocido de backdoor: {conn.LocalEndPoint}:{conn.LocalEndPoint.Port} -> {conn.RemoteEndPoint}";
                    EmitNetworkAlert(msg, ThreatLevel.Critical,
                        threatType: "Backdoor",
                        description: $"Conexión establecida en el puerto {conn.LocalEndPoint.Port}, comúnmente utilizado por backdoors para recibir comandos de atacantes.",
                        srcIp: conn.LocalEndPoint.Address.ToString(), srcPort: conn.LocalEndPoint.Port,
                        dstIp: conn.RemoteEndPoint.Address.ToString(), dstPort: conn.RemoteEndPoint.Port);
                }

                if (backdoorPorts.Contains(conn.RemoteEndPoint.Port))
                {
                    var msg = $"[Backdoor] Conexión saliente a puerto de backdoor: {conn.RemoteEndPoint}";
                    EmitNetworkAlert(msg, ThreatLevel.Critical,
                        threatType: "Backdoor",
                        description: $"Conexión saliente hacia {conn.RemoteEndPoint} en un puerto comúnmente asociado con backdoors.",
                        srcIp: conn.LocalEndPoint.Address.ToString(), srcPort: conn.LocalEndPoint.Port,
                        dstIp: conn.RemoteEndPoint.Address.ToString(), dstPort: conn.RemoteEndPoint.Port);
                }

                // Check remote endpoint against C2/botnet IoC database
                var remoteIp = conn.RemoteEndPoint.Address.ToString();
                if (_threatDb != null && !IsLocalAddress(conn.RemoteEndPoint.Address))
                {
                    if (_threatDb.IsKnownC2Ip(remoteIp))
                    {
                        var key = $"c2_{remoteIp}";
                        if (!_alertCooldown.ContainsKey(key))
                        {
                            _alertCooldown[key] = DateTime.Now;
                            var msg = $"[Botnet/C2] Conexión a servidor de comando y control: {conn.LocalEndPoint} -> {conn.RemoteEndPoint} ({_threatDb.GetSourceCount(remoteIp)} fuentes)";
                            EmitNetworkAlert(msg, ThreatLevel.Critical,
                                threatType: "C2/Botnet",
                                description: $"Conexión detectada hacia un servidor de Comando y Control (C2) conocido en {remoteIp}:{conn.RemoteEndPoint.Port}. Este servidor es utilizado por botnets para emitir instrucciones a sistemas infectados y robar datos. Reportado por {_threatDb.GetSourceCount(remoteIp)} fuentes de inteligencia de amenazas.",
                                dstIp: remoteIp, dstPort: conn.RemoteEndPoint.Port,
                                srcIp: conn.LocalEndPoint.Address.ToString(), srcPort: conn.LocalEndPoint.Port);
                        }
                    }
                    else if (_threatDb.IsKnownBotnetIp(remoteIp))
                    {
                        var key = $"bot_{remoteIp}";
                        if (!_alertCooldown.ContainsKey(key))
                        {
                            _alertCooldown[key] = DateTime.Now;
                            var msg = $"[Botnet] Conexión a IP de botnet conocida: {conn.RemoteEndPoint}";
                            EmitNetworkAlert(msg, ThreatLevel.High,
                                threatType: "Botnet",
                                description: $"Conexión a una dirección IP asociada con botnets: {remoteIp}:{conn.RemoteEndPoint.Port}. El sistema podría estar infectado y formando parte de una red de bots.",
                                dstIp: remoteIp, dstPort: conn.RemoteEndPoint.Port,
                                srcIp: conn.LocalEndPoint.Address.ToString(), srcPort: conn.LocalEndPoint.Port);
                        }
                    }
                }
            }
        }
        catch { }
    }

    public void DetectUnauthorizedRemoteConnections()
    {
        try
        {
            var rdpPort = 3389;
            var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
            if (listeners.Any(l => l.Port == rdpPort))
            {
                var key = "rdp_listener";
                if (!_alertCooldown.ContainsKey(key))
                {
                    _alertCooldown[key] = DateTime.Now;
                    var msg = $"[Red] Escritorio Remoto (RDP) activo en puerto {rdpPort} - verificar si es autorizado";
                    EmitNetworkAlert(msg, ThreatLevel.Medium,
                        threatType: "RDP",
                        description: "El servicio de Escritorio Remoto (RDP) está activo en el puerto 3389. Si no necesita acceso remoto, considere desactivarlo para reducir la superficie de ataque.",
                        dstPort: rdpPort);
                }
            }

            var tcpConnections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
            var established = tcpConnections.Where(c =>
                c.State == TcpState.Established && !IsLocalAddress(c.RemoteEndPoint.Address));

            foreach (var conn in established)
            {
                var remoteIp = conn.RemoteEndPoint.Address.ToString();
                if (_knownRemoteIps.Contains(remoteIp)) continue;

                if (IsSuspiciousRemoteIp(remoteIp))
                {
                    var key = $"remote_{remoteIp}_{conn.RemoteEndPoint.Port}";
                    if (!_alertCooldown.ContainsKey(key))
                    {
                        _alertCooldown[key] = DateTime.Now;
                        var msg = $"[Red] Conexión remota no autorizada: {conn.LocalEndPoint} -> {conn.RemoteEndPoint} (país sospechoso)";
                        EmitNetworkAlert(msg, ThreatLevel.High,
                            threatType: "ConexionRemota",
                            description: $"Conexión remota no autorizada hacia {conn.RemoteEndPoint.Address}:{conn.RemoteEndPoint.Port}. La IP de destino está en un rango asociado con países de alto riesgo.",
                            dstIp: remoteIp, dstPort: conn.RemoteEndPoint.Port,
                            srcIp: conn.LocalEndPoint.Address.ToString(), srcPort: conn.LocalEndPoint.Port);
                    }
                }
                else if (_threatDb != null && _threatDb.IsKnownC2Ip(remoteIp))
                {
                    var key = $"c2_{remoteIp}";
                    if (!_alertCooldown.ContainsKey(key))
                    {
                        _alertCooldown[key] = DateTime.Now;
                        var msg = $"[C2/Botnet] Conexión remota a servidor C2 conocido: {conn.RemoteEndPoint}";
                        EmitNetworkAlert(msg, ThreatLevel.Critical,
                            threatType: "C2/Botnet",
                            description: $"Conexión remota a un servidor C2 conocido en {remoteIp}:{conn.RemoteEndPoint.Port}. Los servidores C2 son utilizados por malware para recibir instrucciones.",
                            dstIp: remoteIp, dstPort: conn.RemoteEndPoint.Port,
                            srcIp: conn.LocalEndPoint.Address.ToString(), srcPort: conn.LocalEndPoint.Port);
                    }
                }
                else if (_threatDb != null && _threatDb.IsKnownBotnetIp(remoteIp))
                {
                    var key = $"bot_{remoteIp}";
                    if (!_alertCooldown.ContainsKey(key))
                    {
                        _alertCooldown[key] = DateTime.Now;
                        var msg = $"[Botnet] Conexión a botnet conocida: {conn.RemoteEndPoint}";
                        EmitNetworkAlert(msg, ThreatLevel.High,
                            threatType: "Botnet",
                            description: $"Conexión a {remoteIp}:{conn.RemoteEndPoint.Port}, una IP asociada con actividad de botnet. El sistema podría estar infectado.",
                            dstIp: remoteIp, dstPort: conn.RemoteEndPoint.Port,
                            srcIp: conn.LocalEndPoint.Address.ToString(), srcPort: conn.LocalEndPoint.Port);
                    }
                }
                else
                {
                    _knownRemoteIps.Add(remoteIp);
                }
            }
        }
        catch { }
    }

    public void DetectReverseShells()
    {
        try
        {
            var properties = IPGlobalProperties.GetIPGlobalProperties();
            var tcpConnections = properties.GetActiveTcpConnections();

            var shellProcesses = new[] { "cmd", "powershell", "pwsh", "bash", "sh", "python", "perl", "nc", "ncat", "socat" };
            var processConnections = new Dictionary<int, (int pid, string name)>();

            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    var name = proc.ProcessName.ToLowerInvariant();
                    if (shellProcesses.Any(s => name.StartsWith(s)))
                        processConnections[proc.Id] = (proc.Id, proc.ProcessName);
                }
                catch { }
            }

            var reverseShellPorts = new HashSet<int> { 4444, 5555, 6666, 7777, 8888, 9999, 1337, 4443, 4445, 9001, 9002 };

            foreach (var conn in tcpConnections)
            {
                if (conn.State != TcpState.Established) continue;

                    if (reverseShellPorts.Contains(conn.RemoteEndPoint.Port))
                    {
                        var key = $"rs_{conn.RemoteEndPoint}";
                        if (!_alertCooldown.ContainsKey(key))
                        {
                            _alertCooldown[key] = DateTime.Now;
                            var msg = $"[Reverse Shell] Posible shell inversa detectada: conexión a {conn.RemoteEndPoint}";
                            EmitNetworkAlert(msg, ThreatLevel.Critical,
                                threatType: "ReverseShell",
                                description: $"Posible shell inversa detectada: conexión establecida hacia {conn.RemoteEndPoint.Address}:{conn.RemoteEndPoint.Port}. Una shell inversa permite a un atacante ejecutar comandos de forma remota en este equipo.",
                                dstIp: conn.RemoteEndPoint.Address.ToString(), dstPort: conn.RemoteEndPoint.Port,
                                srcIp: conn.LocalEndPoint.Address.ToString(), srcPort: conn.LocalEndPoint.Port);
                        }
                    }
            }
        }
        catch { }
    }

    public void DetectWiFiDeauth()
    {
        try
        {
            if (_deauthCooldown > 0)
            {
                _deauthCooldown--;
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

            if (!isDisconnected) return;

            Thread.Sleep(2000);
            using var proc2 = Process.Start(new ProcessStartInfo("netsh", "wlan show interfaces")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });
            if (proc2 == null) return;
            var checkAgain = proc2.StandardOutput.ReadToEnd();
            proc2.WaitForExit(3000);

            if (checkAgain.Contains(" desconectado") || checkAgain.Contains("no está conectado"))
            {
                var msg = "[Deauth] Ataque de desautenticación Wi-Fi detectado: conexión perdida repentinamente";
                EmitNetworkAlert(msg, ThreatLevel.High,
                    threatType: "WiFiDeauth",
                    description: "Ataque de desautenticación Wi-Fi detectado: la conexión inalámbrica se perdió repentinamente dos veces consecutivas. Este ataque fuerza la desconexión de dispositivos para interceptar tráfico o realizar ataques de tipo «evil twin».");
                _deauthCooldown = 12;
            }
        }
        catch { }
    }

    public void DetectNetworkScan()
    {
        try
        {
            if (_scanDetectionCooldown > 0)
            {
                _scanDetectionCooldown--;
                return;
            }

            var properties = IPGlobalProperties.GetIPGlobalProperties();
            var tcpConnections = properties.GetActiveTcpConnections();

            var failedConnections = tcpConnections.Count(c =>
                c.State == TcpState.Closed || c.State == TcpState.CloseWait);

            var halfOpen = tcpConnections.Count(c =>
                c.State == TcpState.SynSent || c.State == TcpState.SynReceived);

            if (halfOpen > 30)
            {
                var msg = $"[Red] Posible escaneo de puertos detectado: {halfOpen} conexiones SYN pendientes";
                EmitNetworkAlert(msg, ThreatLevel.High,
                    threatType: "PortScan",
                    description: $"Posible escaneo de puertos: {halfOpen} conexiones SYN pendientes detectadas. Un atacante podría estar buscando servicios vulnerables en el sistema.");
                _scanDetectionCooldown = 3;
            }
        }
        catch { }
    }

    public void DetectDnsTunneling()
    {
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -Command \"Get-DnsClientCache | Select-Object -ExpandProperty Entry | Select-Object -First 100\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);

            var suspiciousDns = new[] { "dyndns", "duckdns", "no-ip", "ngrok", "serveo", "localtunnel" };
            foreach (var entry in output.Split('\n'))
            {
                var e = entry.Trim().ToLowerInvariant();
                if (string.IsNullOrEmpty(e)) continue;
                    if (suspiciousDns.Any(s => e.Contains(s)))
                    {
                        var key = $"dns_{e}";
                        if (!_alertCooldown.ContainsKey(key))
                        {
                            _alertCooldown[key] = DateTime.Now;
                            var msg = $"[Red] DNS tunneling sospechoso: {e} (posible C2)";
                            EmitNetworkAlert(msg, ThreatLevel.High,
                                threatType: "DnsTunneling",
                                description: $"Consulta DNS sospechosa a '{e}'. Los servicios de DNS dinámico son frecuentemente utilizados por malware para establecer canales C2 evasivos.");
                        }
                    }

                    // Check against known malware domains from IoC feeds
                    if (_threatDb != null && _threatDb.IsKnownMalwareDomain(e))
                    {
                        var key = $"iocdns_{e}";
                        if (!_alertCooldown.ContainsKey(key))
                        {
                            _alertCooldown[key] = DateTime.Now;
                            var msg = $"[Malware] Consulta DNS a dominio malicioso conocido: {e}";
                            EmitNetworkAlert(msg, ThreatLevel.Critical,
                                threatType: "Malware",
                                description: $"Consulta DNS a un dominio malicioso conocido: '{e}'. Este dominio está reportado en bases de inteligencia de amenazas como distribuidor de malware o C2.");
                        }
                    }
            }
        }
        catch { }
    }

    private static string GetPortServiceName(int port) => port switch
    {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        135 => "RPC",
        137 => "NetBIOS",
        139 => "NetBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        1433 => "MSSQL",
        1521 => "Oracle",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        8080 => "HTTP-Alt",
        27017 => "MongoDB",
        _ => "Desconocido"
    };

    private static ThreatLevel GetPortThreatLevel(int port) => port switch
    {
        21 or 23 or 135 or 137 or 139 or 445 => ThreatLevel.High,
        22 or 1433 or 3306 or 3389 or 5900 or 6379 => ThreatLevel.Medium,
        _ => ThreatLevel.Low
    };

    private static bool IsLocalAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address)) return true;
        var bytes = address.GetAddressBytes();
        if (bytes[0] == 10) return true;
        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
        if (bytes[0] == 192 && bytes[1] == 168) return true;
        if (bytes[0] == 169 && bytes[1] == 254) return true;
        return false;
    }

    private static bool IsSuspiciousRemoteIp(string ip)
    {
        // NOTA: NO bloquear rangos completos de países - eso causa falsos positivos masivos
        // en entornos corporativos. Las IPs sospechosas deben detectarse mediante
        // IoC (threat database), no por rango de IP.
        // Esta función ahora siempre devuelve false; la detección se hace en ThreatDatabase.
        return false;
    }

    private void EmitNetworkAlert(string msg, ThreatLevel level,
        string? threatType = null, string? description = null,
        string? srcIp = null, int srcPort = 0,
        string? dstIp = null, int dstPort = 0)
    {
        var entry = new LogEntry
        {
            Event = msg,
            FilePath = dstIp ?? srcIp ?? "",
            ActionTaken = $"Alerta de red {level}",
            User = Environment.UserName,
            Description = description ?? GenerateDefaultDescription(threatType, msg),
            ThreatType = threatType ?? "Desconocido",
            SourceIp = srcIp,
            SourcePort = srcPort,
            DestinationIp = dstIp,
            DestinationPort = dstPort,
            Level = level
        };

        NetworkAlert?.Invoke(entry);
        _log?.Log(entry);

        if (level == ThreatLevel.Critical || level == ThreatLevel.High)
        {
            var targetIp = dstIp ?? srcIp;
            if (!string.IsNullOrEmpty(targetIp))
            {
                _shield?.BlockIp(targetIp);

                _tts?.Speak("Amenaza de red bloqueada automáticamente por Secure AI Plus.");
            }

            var report = new ThreatReport
            {
                ThreatType = threatType ?? "Desconocido",
                Description = description ?? GenerateDefaultDescription(threatType, msg),
                SourceIp = srcIp,
                SourcePort = srcPort,
                DestinationIp = dstIp,
                DestinationPort = dstPort,
                Level = level,
                ActionTaken = $"Bloqueo automático de IP {targetIp} por firewall",
                RawAlert = msg
            };
            _reports?.GenerateReport(report);

            _log?.Log(new LogEntry
            {
                Event = $"[AI Red] Amenaza eliminada automáticamente: {threatType ?? "Red"} - IP {targetIp} bloqueada",
                FilePath = targetIp ?? "",
                ActionTaken = "Auto-bloqueo por AI Experta en Red",
                User = "Secure AI Plus",
                Description = $"La AI Experta en Red detectó y bloqueó automáticamente la amenaza. {description}",
                ThreatType = threatType,
                SourceIp = srcIp,
                SourcePort = srcPort,
                DestinationIp = dstIp,
                DestinationPort = dstPort,
                Level = level
            });
        }
    }

    private static string GenerateDefaultDescription(string? threatType, string msg)
    {
        return threatType switch
        {
            "DoS/DDoS" => "Ataque de Denegación de Servicio: tasa anormalmente alta de conexiones de red que podría saturar los recursos del sistema y hacerlo inaccesible.",
            "Backdoor" => "Puerta trasera: se detectó una conexión en un puerto comúnmente utilizado por malware para establecer acceso remoto no autorizado al sistema.",
            "ReverseShell" => "Shell inversa: un proceso está intentando establecer una conexión saliente hacia un atacante, dándole control remoto del sistema.",
            "C2/Botnet" => "Comando y Control: conexión a un servidor C2 conocido utilizado por botnets para recibir instrucciones y exfiltrar datos.",
            "Botnet" => "Botnet: conexión a una dirección IP asociada con redes de bots, lo que indica posible infección.",
            "PortScan" => "Escaneo de puertos: posible reconocimiento de red, a menudo precursor de un ataque dirigido.",
            "WiFiDeauth" => "Desautenticación Wi-Fi: ataque que fuerza la desconexión de dispositivos de la red inalámbrica, posiblemente para interceptar tráfico.",
            "DnsTunneling" => "Túnel DNS: uso del protocolo DNS para evadir firewalls y establecer comunicaciones con servidores remotos no autorizados.",
            "RDP" => "Escritorio Remoto: el servicio RDP está activo, lo que podría ser un vector de ataque si no está configurado correctamente.",
            _ => "Amenaza de red detectada por Secure AI. Verifique los detalles para determinar si requiere acción."
        };
    }
}
