using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Text;
using Secureia.Models;

namespace Secureia.Services;

public class DefenseShieldAI
{
    private readonly TtsService? _tts;
    private readonly LogService? _log;
    private readonly ExpertMalwareAI? _expertMalware;
    private readonly ExpertNetworkAI? _expertNetwork;
    private bool _shieldActive;
    private DateTime _shieldActivatedAt;
    private readonly HashSet<int> _blockedPids = new();
    private readonly HashSet<string> _blockedIps = new();
    private int _aggressionLevel;

    public bool IsShieldActive => _shieldActive;
    public int AggressionLevel => _aggressionLevel;
    public string ShieldStatus => _shieldActive
        ? $"ESCUDO ACTIVO - Nivel {_aggressionLevel} - Activado: {_shieldActivatedAt:HH:mm:ss}"
        : "Escudo inactivo";

    public event Action<string, int>? ShieldStatusChanged;
    public event Action<string>? EmergencyAlert;

    public DefenseShieldAI(TtsService? tts = null, LogService? log = null,
                           ExpertMalwareAI? expertMalware = null,
                           ExpertNetworkAI? expertNetwork = null)
    {
        _tts = tts;
        _log = log;
        _expertMalware = expertMalware;
        _expertNetwork = expertNetwork;
    }

    public void AssessThreat(string threatDescription, ThreatLevel level)
    {
        if (!_shieldActive && level == ThreatLevel.Critical)
        {
            ActivateShield(3, $"Amenaza crítica: {threatDescription}");
        }
        else if (!_shieldActive && level == ThreatLevel.High)
        {
            ActivateShield(2, $"Amenaza alta: {threatDescription}");
        }
        else if (_shieldActive)
        {
            if (level == ThreatLevel.Critical && _aggressionLevel < 3)
                EscalateShield(3, $"Escalada por amenaza crítica: {threatDescription}");
            else if (level == ThreatLevel.High && _aggressionLevel < 2)
                EscalateShield(2, $"Escalada por amenaza alta: {threatDescription}");
        }
    }

    public void ActivateShield(int level, string reason)
    {
        if (_shieldActive && level <= _aggressionLevel) return;

        // NUNCA bloquear internet del usuario. Nivel máximo permitido es 1
        // (monitoreo intensificado). Niveles 2-3 solo se activan para ransomware
        // confirmado donde aislar el equipo local tiene sentido.
        if (level > 1 && !reason.Contains("ransomware", StringComparison.OrdinalIgnoreCase)
                      && !reason.Contains("ransom", StringComparison.OrdinalIgnoreCase))
        {
            level = 1;
        }

        _shieldActive = true;
        _shieldActivatedAt = DateTime.Now;
        _aggressionLevel = Math.Max(_aggressionLevel, level);

        var msg = $"[ESCUDO] Activado nivel {_aggressionLevel}: {reason}";
        EmergencyAlert?.Invoke(msg);
        ShieldStatusChanged?.Invoke(msg, _aggressionLevel);

        _log?.Log(new LogEntry
        {
            Event = $"ESCUDO DE DEFENSA activado (nivel {_aggressionLevel}): {reason}",
            ActionTaken = "Activación de escudo",
            User = Environment.UserName
        });

        _tts?.Speak("¡Activando medidas de seguridad! Escudo de defensa activado.");

        Task.Run(async () =>
        {
            switch (_aggressionLevel)
            {
                case 1:
                    await ApplyLevel1Defenses();
                    break;
                case 2:
                    await ApplyLevel1Defenses();
                    await ApplyLevel2Defenses();
                    break;
                case 3:
                    await ApplyLevel1Defenses();
                    await ApplyLevel2Defenses();
                    await ApplyLevel3Defenses();
                    break;
            }
        });
    }

    public void EscalateShield(int level, string reason)
    {
        ActivateShield(level, reason);
    }

    public async void DeactivateShield()
    {
        if (!_shieldActive) return;
        _shieldActive = false;
        _aggressionLevel = 0;

        var msg = "[ESCUDO] Escudo desactivado - sistema normalizado";
        ShieldStatusChanged?.Invoke(msg, 0);

        _log?.Log(new LogEntry
        {
            Event = "ESCUDO DE DEFENSA desactivado - limpiando reglas de firewall",
            ActionTaken = "Desactivación de escudo",
            User = Environment.UserName
        });

        _tts?.Speak("Escudo de seguridad desactivado. Sistema normalizado.");

        // Limpiar todas las reglas de firewall que haya creado el escudo
        await RemoveFirewallRulesAsync();
    }

    public void MonitorThreats()
    {
        if (!_shieldActive) return;

        if (_aggressionLevel >= 2)
        {
            MonitorProcessCreation();
            MonitorNetworkConnections();
            MonitorFileSystemChanges();
        }
    }

    private void MonitorProcessCreation()
    {
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (_blockedPids.Contains(proc.Id)) continue;

                try
                {
                    var name = proc.ProcessName.ToLowerInvariant();
                    var dangerousProcesses = new[]
                    {
                        "cmd", "powershell", "pwsh", "wscript", "cscript",
                        "mshta", "regedit", "taskkill", "wmic",
                        "rundll32", "regsvr32", "msiexec"
                    };

                    if (dangerousProcesses.Contains(name) && _aggressionLevel >= 3)
                    {
                        try { proc.Kill(); } catch { }
                        _blockedPids.Add(proc.Id);
                        var msg = $"[ESCUDO] Proceso bloqueado: {name} (PID: {proc.Id})";
                        EmergencyAlert?.Invoke(msg);
                        _log?.Log(new LogEntry
                        {
                            Event = msg,
                            ActionTaken = "Bloqueo por escudo",
                            User = Environment.UserName
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void MonitorNetworkConnections()
    {
        try
        {
            var properties = IPGlobalProperties.GetIPGlobalProperties();
            var connections = properties.GetActiveTcpConnections();

            foreach (var conn in connections)
            {
                if (conn.State != TcpState.Established) continue;
                var remoteIp = conn.RemoteEndPoint.Address.ToString();

                if (_blockedIps.Contains(remoteIp)) continue;

                var suspiciousPorts = new[] { 4444, 5555, 6666, 7777, 8888, 9999, 1337, 4443, 31337, 12345 };
                if (suspiciousPorts.Contains(conn.RemoteEndPoint.Port) || _aggressionLevel >= 3)
                {
                    _blockedIps.Add(remoteIp);
                    var msg = $"[ESCUDO] Bloqueando conexión a {remoteIp}:{conn.RemoteEndPoint.Port}";
                    EmergencyAlert?.Invoke(msg);
                }
            }
        }
        catch { }
    }

    private void MonitorFileSystemChanges()
    {
        try
        {
            var sensitiveDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
            };

            foreach (var dir in sensitiveDirs)
            {
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.*", SearchOption.TopDirectoryOnly))
                    {
                        var ext = Path.GetExtension(file)?.ToLowerInvariant() ?? "";
                        var dangerousExts = new HashSet<string> { ".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".js" };
                        if (dangerousExts.Contains(ext))
                        {
                            var fi = new FileInfo(file);
                            if (fi.CreationTime > _shieldActivatedAt)
                            {
                                var msg = $"[ESCUDO] Archivo sospechoso creado durante ataque: {file}";
                                EmergencyAlert?.Invoke(msg);
                                _log?.Log(new LogEntry
                                {
                                    Event = msg,
                                    FilePath = file,
                                    ActionTaken = "Alerta de escudo",
                                    User = Environment.UserName
                                });
                            }
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private Task ApplyLevel1Defenses()
    {
        _tts?.Speak("Nivel uno de defensa activado. Monitoreo intensificado.");
        return Task.CompletedTask;
    }

    private async Task ApplyLevel2Defenses()
    {
        _tts?.Speak("Nivel dos de defensa. Bloqueando conexiones sospechosas.");

        // IMPORTANTE: NUNCA bloquear todo el tráfico de salida (remoteip=any en dir=out).
        // Eso deja la PC sin internet, lo cual es inaceptable en cualquier entorno.
        // Solo se bloquean IPs específicas de amenazas confirmadas (ver BlockIp).
        // El bloqueo masivo de entrada es demasiado agresivo para uso general;
        // en su lugar, solo aplicamos reglas específicas contra amenazas conocidas.

        // Bloquear tráfico entrante solo si hay una amenaza crítica activa
        // (no remoto=any, solo bloquear por protocolos inseguros)
        try
        {
            var dangerousPorts = new[] { 135, 137, 139, 445, 3389 };
            foreach (var port in dangerousPorts)
            {
                var ruleName = $"SecureAI_Shield_BlockPort_{port}";
                try
                {
                    var psi = new ProcessStartInfo("netsh",
                        $"advfirewall firewall add rule name=\"{ruleName}\" dir=in action=block protocol=tcp localport={port}")
                    {
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    using var proc = Process.Start(psi);
                    if (proc != null) await proc.WaitForExitAsync();
                }
                catch { }
            }
        }
        catch { }

        await Task.CompletedTask;
    }

    private async Task ApplyLevel3Defenses()
    {
        _tts?.Speak("¡Nivel tres de defensa! Emergencia máxima. Bloqueo total activado.");

        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -Command \"Stop-Service -Name 'RemoteRegistry','RemoteAccess','TermService','SharedAccess' -Force -ErrorAction SilentlyContinue; Set-Service -Name 'RemoteRegistry' -StartupType Disabled -ErrorAction SilentlyContinue\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc != null) await proc.WaitForExitAsync();
        }
        catch { }
    }

    public void BlockIp(string ip)
    {
        if (_blockedIps.Contains(ip)) return;
        _blockedIps.Add(ip);

        var msg = $"[ESCUDO] Bloqueando IP por amenaza de red: {ip}";
        EmergencyAlert?.Invoke(msg);
        _log?.Log(new LogEntry
        {
            Event = msg,
            FilePath = ip,
            ActionTaken = "Bloqueo de IP por escudo",
            User = Environment.UserName
        });

        Task.Run(async () =>
        {
            try
            {
                var ruleName = $"SecureAI_Block_{ip.Replace('.', '_')}";
                var psi1 = new ProcessStartInfo("netsh",
                    $"advfirewall firewall add rule name=\"{ruleName}_in\" dir=in action=block remoteip={ip} protocol=any")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc1 = Process.Start(psi1);
                if (proc1 != null) await proc1.WaitForExitAsync();

                var psi2 = new ProcessStartInfo("netsh",
                    $"advfirewall firewall add rule name=\"{ruleName}_out\" dir=out action=block remoteip={ip} protocol=any")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc2 = Process.Start(psi2);
                if (proc2 != null) await proc2.WaitForExitAsync();
            }
            catch { }
        });
    }

    public void UnblockIp(string ip)
    {
        if (!_blockedIps.Contains(ip)) return;
        _blockedIps.Remove(ip);

        Task.Run(async () =>
        {
            try
            {
                var ruleName = $"SecureAI_Block_{ip.Replace('.', '_')}";
                var psi1 = new ProcessStartInfo("netsh",
                    $"advfirewall firewall delete rule name=\"{ruleName}_in\"")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc1 = Process.Start(psi1);
                if (proc1 != null) await proc1.WaitForExitAsync();

                var psi2 = new ProcessStartInfo("netsh",
                    $"advfirewall firewall delete rule name=\"{ruleName}_out\"")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc2 = Process.Start(psi2);
                if (proc2 != null) await proc2.WaitForExitAsync();
            }
            catch { }
        });
    }

    public async Task RemoveFirewallRulesAsync()
    {
        // Limpiar reglas viejas (versiones anteriores) que bloqueaban todo el tráfico
        var oldRuleNames = new[] { "SecureAI_Shield_BlockAll", "SecureAI_Shield_BlockOut" };
        foreach (var oldRule in oldRuleNames)
        {
            try
            {
                var psi = new ProcessStartInfo("netsh", $"advfirewall firewall delete rule name=\"{oldRule}\"")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                if (proc != null) await proc.WaitForExitAsync();
            }
            catch { }
        }

        var dangerousPorts = new[] { 135, 137, 139, 445, 3389 };
        foreach (var port in dangerousPorts)
        {
            try
            {
                var ruleName = $"SecureAI_Shield_BlockPort_{port}";
                var psi = new ProcessStartInfo("netsh", $"advfirewall firewall delete rule name=\"{ruleName}\"")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                if (proc != null) await proc.WaitForExitAsync();
            }
            catch { }
        }

        foreach (var ip in _blockedIps.ToList())
        {
            UnblockIp(ip);
        }
    }
}
