using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;

namespace Secureia.Services;

public class WindowsDefenderService
{
    private bool _defenderDisabled;
    private bool _realtimeMonitoringOff;
    private string _status = "Desconocido";
    private DateTime _lastCheck;

    public bool IsDefenderDisabled => _defenderDisabled;
    public bool IsRealtimeMonitoringOff => _realtimeMonitoringOff;
    public string Status => _status;

    public event Action<string>? StatusChanged;

    public async Task<DefenderStatus> CheckDefenderStatusAsync()
    {
        var result = new DefenderStatus();

        try
        {
            var psi = new ProcessStartInfo("powershell.exe")
            {
                Arguments = "-NoProfile -Command \"Get-MpComputerStatus | Select-Object -Property RealTimeProtectionEnabled, AntivirusEnabled, AMServiceEnabled, IoavProtectionEnabled, NISEnabled, TamperProtectionSource | ConvertTo-Json\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc == null)
            {
                result.IsAvailable = false;
                _status = "No se pudo consultar Windows Defender";
                return result;
            }

            var output = await proc.StandardOutput.ReadToEndAsync();
            await proc.WaitForExitAsync();

            if (!string.IsNullOrEmpty(output) && output.Contains("RealTimeProtectionEnabled"))
            {
                result.IsAvailable = true;

                var match = Regex.Match(output, @"""RealTimeProtectionEnabled""\s*:\s*(true|false)", RegexOptions.IgnoreCase);
                if (match.Success)
                    result.RealTimeProtectionEnabled = match.Groups[1].Value.Equals("true", StringComparison.OrdinalIgnoreCase);

                match = Regex.Match(output, @"""AntivirusEnabled""\s*:\s*(true|false)", RegexOptions.IgnoreCase);
                if (match.Success)
                    result.AntivirusEnabled = match.Groups[1].Value.Equals("true", StringComparison.OrdinalIgnoreCase);

                match = Regex.Match(output, @"""TamperProtectionSource""\s*:\s*(\d+)", RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    var tpSource = int.Parse(match.Groups[1].Value);
                    result.TamperProtectionEnabled = tpSource != 0;
                }
            }
            else
            {
                result.IsAvailable = false;
                _status = "Windows Defender no disponible o no se pudo consultar";
            }

            _realtimeMonitoringOff = result.IsAvailable && !result.RealTimeProtectionEnabled;
            _defenderDisabled = result.IsAvailable && !result.AntivirusEnabled;

            if (!result.IsAvailable)
                _status = "No disponible";
            else if (!result.AntivirusEnabled)
                _status = "Defensor desactivado";
            else if (!result.RealTimeProtectionEnabled)
                _status = "Protección en tiempo real desactivada";
            else if (result.TamperProtectionEnabled)
                _status = "Protección contra manipulaciones activa";
            else
                _status = "Protegiendo";

            _lastCheck = DateTime.Now;
            StatusChanged?.Invoke(_status);
        }
        catch
        {
            result.IsAvailable = false;
            _status = "Error al consultar";
        }

        return result;
    }

    private Task<bool> RunPowershellElevatedAsync(string arguments)
    {
        return Task.Run(() =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell.exe")
                {
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass {arguments}",
                    UseShellExecute = true,
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
                if (proc == null) return false;

                var exited = proc.WaitForExit(90_000);
                if (!exited)
                {
                    try { proc.Kill(); } catch { }
                    return false;
                }

                return proc.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        });
    }

    public async Task<bool> DisableRealtimeMonitoringAsync()
    {
        var ok = await RunPowershellElevatedAsync(
            "-Command \"Set-MpPreference -DisableRealtimeMonitoring $true\"");
        if (ok)
        {
            _realtimeMonitoringOff = true;
            _status = "Protección en tiempo real desactivada";
            StatusChanged?.Invoke(_status);
        }
        else
        {
            _status = "Error al desactivar monitoreo en tiempo real (¿Trampa de seguridad activa?)";
            StatusChanged?.Invoke(_status);
        }
        return ok;
    }

    public Task<bool> DisableTamperProtectionAsync()
    {
        return Task.Run(() =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell.exe")
                {
                    Arguments = "-NoProfile -ExecutionPolicy Bypass -Command \"New-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Features' -Name 'TamperProtection' -Force -ErrorAction SilentlyContinue | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Features' -Name 'TamperProtection' -Value 0 -Type DWord -Force\"",
                    UseShellExecute = true,
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                using var proc = Process.Start(psi);
                if (proc != null) proc.WaitForExit(30_000);
                return true;
            }
            catch
            {
                return false;
            }
        });
    }

    public async Task<bool> DisableDefenderAsync()
    {
        var exePath = Process.GetCurrentProcess().MainModule?.FileName;
        if (!string.IsNullOrEmpty(exePath))
        {
            var exeDir = Path.GetDirectoryName(exePath);
            if (!string.IsNullOrEmpty(exeDir))
                await AddExclusionAsync(exeDir);
        }

        var localAppData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Secureia");
        if (Directory.Exists(localAppData))
            await AddExclusionAsync(localAppData);

        // Paso 1: Intentar desactivar Tamper Protection
        var tamperStatus = await CheckDefenderStatusAsync();
        if (tamperStatus.TamperProtectionEnabled)
        {
            await DisableTamperProtectionAsync();
            await Task.Delay(2000);
        }

        // Paso 2: Desactivar protecciones individualmente (más tolerante a fallos)
        var disableCmds = new[]
        {
            "Set-MpPreference -DisableRealtimeMonitoring $true -Force",
            "Set-MpPreference -DisableBehaviorMonitoring $true -Force",
            "Set-MpPreference -DisableIOAVProtection $true -Force",
            "Set-MpPreference -DisableScriptScanning $true -Force",
            "Set-MpPreference -DisableBlockAtFirstSeen $true -Force"
        };

        foreach (var cmd in disableCmds)
        {
            var script = $"-NoProfile -ExecutionPolicy Bypass -Command \"{cmd}; if ($?) {{ exit 0 }} else {{ exit 1 }}\"";
            try
            {
                await RunPowershellElevatedAsync(script);
            }
            catch { }
            await Task.Delay(500);
        }

        // Verificar resultado
        var status = await CheckDefenderStatusAsync();
        var ok = status.IsAvailable && (!status.RealTimeProtectionEnabled);

        if (ok)
        {
            _defenderDisabled = true;
            _status = "Defensor desactivado - Secure AI activo";
        }
        else
        {
            _status = "No se pudo desactivar completamente. Desactive 'Protección contra manipulaciones' en Seguridad de Windows y vuelva a intentar.";
        }

        StatusChanged?.Invoke(_status);
        return ok;
    }

    public async Task<bool> AddExclusionAsync(string path)
    {
        var escapedPath = path.Replace("'", "''").Replace("`", "``");
        var script = $"-NoProfile -ExecutionPolicy Bypass -Command \"Add-MpPreference -ExclusionPath '{escapedPath}' -ErrorAction SilentlyContinue; Add-MpPreference -ExclusionProcess '{escapedPath.Replace("\\", "\\\\")}' -ErrorAction SilentlyContinue; exit 0\"";
        return await RunPowershellElevatedAsync(script);
    }

    public async Task<bool> EnableSecureAIIntegrationAsync()
    {
        try
        {
            var appPath = Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrEmpty(appPath)) return false;

            var appDir = Path.GetDirectoryName(appPath);
            if (appDir == null) return false;

            var exclusionAdded = await AddExclusionAsync(appDir);
            var defenderDisabled = await DisableDefenderAsync();

            return exclusionAdded && defenderDisabled;
        }
        catch { return false; }
    }

    public async Task<DefenderStatus> RefreshStatusAsync()
    {
        return await CheckDefenderStatusAsync();
    }

    public string GetStatusSummary()
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Estado: {_status}");
        sb.AppendLine($"Última verificación: {(_lastCheck == default ? "Nunca" : _lastCheck.ToString("yyyy-MM-dd HH:mm:ss"))}");
        sb.AppendLine($"Defensor desactivado: {(_defenderDisabled ? "Sí" : "No")}");
        sb.AppendLine($"Monitoreo en tiempo real: {(_realtimeMonitoringOff ? "Desactivado" : "Activo")}");
        return sb.ToString();
    }
}

public class DefenderStatus
{
    public bool IsAvailable { get; set; }
    public bool RealTimeProtectionEnabled { get; set; }
    public bool AntivirusEnabled { get; set; }
    public bool TamperProtectionEnabled { get; set; }
}
