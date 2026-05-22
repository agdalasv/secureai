using System.Windows.Input;
using System.Windows.Threading;
using Secureia.Services;

namespace Secureia.ViewModels;

public class DashboardViewModel : ViewModelBase
{
    private readonly ScanEngine _scanEngine;
    private readonly DefinitionService _defService;
    private readonly WindowsDefenderService _defenderService;
    private bool _isProtected = true;
    private string _protectionStatus = "Sistema Asegurado";
    private int _totalScans;
    private int _threatsFound;
    private int _quarantinedItems;
    private string _lastScanDate = "Nunca";
    private int _scanProgress;
    private int _scanTotal;
    private string _scanStatus = "Listo";
    private double _cpuUsage;
    private double _ramUsage;
    private string _cpuUsageText = "0%";
    private string _ramUsageText = "0%";
    private string _ramDetailText = "0 MB";
    private string _definitionsStatus = "No actualizadas";
    private string _defenderStatus = "Consultando...";
    private string _defenderColor = "#FFB74D";
    private bool _defenderDisabled;
    private DispatcherTimer? _monitorTimer;
    private DateTime _lastCpuCheck = DateTime.UtcNow;
    private TimeSpan _lastCpuTime;
    private long _totalSystemMemory;

    public bool IsProtected
    {
        get => _isProtected;
        set { SetProperty(ref _isProtected, value); OnPropertyChanged(nameof(ProtectionBrush)); }
    }
    public string ProtectionStatus
    {
        get => _protectionStatus;
        set => SetProperty(ref _protectionStatus, value);
    }
    public int TotalScans { get => _totalScans; set => SetProperty(ref _totalScans, value); }
    public int ThreatsFound { get => _threatsFound; set => SetProperty(ref _threatsFound, value); }
    public int QuarantinedItems { get => _quarantinedItems; set => SetProperty(ref _quarantinedItems, value); }
    public string LastScanDate { get => _lastScanDate; set => SetProperty(ref _lastScanDate, value); }
    public int ScanProgress { get => _scanProgress; set => SetProperty(ref _scanProgress, value); }
    public int ScanTotal { get => _scanTotal; set => SetProperty(ref _scanTotal, value); }
    public string ScanStatus { get => _scanStatus; set => SetProperty(ref _scanStatus, value); }
    public string DefinitionsStatus { get => _definitionsStatus; set => SetProperty(ref _definitionsStatus, value); }

    public double CpuUsage
    {
        get => _cpuUsage;
        set => SetProperty(ref _cpuUsage, value);
    }
    public double RamUsage
    {
        get => _ramUsage;
        set => SetProperty(ref _ramUsage, value);
    }
    public string CpuUsageText
    {
        get => _cpuUsageText;
        set => SetProperty(ref _cpuUsageText, value);
    }
    public string RamUsageText
    {
        get => _ramUsageText;
        set => SetProperty(ref _ramUsageText, value);
    }
    public string RamDetailText
    {
        get => _ramDetailText;
        set => SetProperty(ref _ramDetailText, value);
    }
    public string DefenderStatus
    {
        get => _defenderStatus;
        set => SetProperty(ref _defenderStatus, value);
    }
    public string DefenderColor
    {
        get => _defenderColor;
        set => SetProperty(ref _defenderColor, value);
    }
    public bool DefenderDisabled
    {
        get => _defenderDisabled;
        set => SetProperty(ref _defenderDisabled, value);
    }

    public string ProtectionColor => IsProtected ? "#00C853" : "#FF5252";
    public System.Windows.Media.Brush ProtectionBrush => IsProtected
        ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0, 200, 83))
        : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 82, 82));

    private string _shieldStatus = "Inactivo";
    private string _shieldLevel = "";
    private string _usbScanStatus = "";
    private bool _shieldActive;

    public string ShieldStatus { get => _shieldStatus; set => SetProperty(ref _shieldStatus, value); }
    public string ShieldLevel { get => _shieldLevel; set => SetProperty(ref _shieldLevel, value); }
    public string UsbScanStatus { get => _usbScanStatus; set => SetProperty(ref _usbScanStatus, value); }
    public bool ShieldActive { get => _shieldActive; set => SetProperty(ref _shieldActive, value); }
    public System.Windows.Media.Brush ShieldColorBrush => ShieldActive
        ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 82, 82))
        : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(129, 199, 132));

    public ICommand UpdateDefinitionsCommand { get; }
    public ICommand RefreshDefenderCommand { get; }

    public DashboardViewModel(ScanEngine scanEngine, DefinitionService defService,
                               WindowsDefenderService defenderService)
    {
        _scanEngine = scanEngine;
        _defService = defService;
        _defenderService = defenderService;

        _scanEngine.ProgressChanged += (processed, total) =>
        {
            ScanProgress = processed;
            ScanTotal = total;
        };
        _scanEngine.StatusChanged += status =>
        {
            ScanStatus = status;
            if (status.Contains("completado", StringComparison.OrdinalIgnoreCase))
            {
                TotalScans++;
                LastScanDate = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
            }
        };
        _scanEngine.ThreatDetected += threat => ThreatsFound++;

        UpdateDefinitionsCommand = new RelayCommand(async _ => await UpdateDefinitions());
        RefreshDefenderCommand = new RelayCommand(async _ => await RefreshDefenderStatusAsync());

        _lastCpuTime = System.Diagnostics.Process.GetCurrentProcess().TotalProcessorTime;
        _totalSystemMemory = GetTotalPhysicalMemoryMb();
        StartMonitoring();

        _ = RefreshDefenderStatusAsync();
    }

    public Task RefreshDefenderStatus()
    {
        return RefreshDefenderStatusAsync();
    }

    private async Task RefreshDefenderStatusAsync()
    {
        try
        {
            var status = await _defenderService.CheckDefenderStatusAsync();
            if (status.IsAvailable)
            {
                if (!status.AntivirusEnabled || !status.RealTimeProtectionEnabled)
                {
                    DefenderStatus = "Secure AI activo - Defender desactivado";
                    DefenderColor = "#00C853";
                    DefenderDisabled = true;
                }
                else if (status.TamperProtectionEnabled)
                {
                    DefenderStatus = "Protección contra manipulaciones activa";
                    DefenderColor = "#FFB74D";
                    DefenderDisabled = false;
                }
                else
                {
                    DefenderStatus = "Defender activo - Haz clic para desactivar";
                    DefenderColor = "#FF5252";
                    DefenderDisabled = false;
                }
            }
            else
            {
                DefenderStatus = "No se pudo consultar Defender";
                DefenderColor = "#888";
                DefenderDisabled = false;
            }
        }
        catch
        {
            DefenderStatus = "Error al consultar";
            DefenderColor = "#FF5252";
        }
    }

    private void StartMonitoring()
    {
        _monitorTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _monitorTimer.Tick += (_, _) =>
        {
            try
            {
                var proc = System.Diagnostics.Process.GetCurrentProcess();

                var now = DateTime.UtcNow;
                var currentCpuTime = proc.TotalProcessorTime;
                var elapsedSec = (now - _lastCpuCheck).TotalSeconds;
                if (elapsedSec > 0)
                {
                    var cpuMs = (currentCpuTime - _lastCpuTime).TotalMilliseconds;
                    var pct = cpuMs / (elapsedSec * 1000.0 * Environment.ProcessorCount) * 100.0;
                    CpuUsage = Math.Min(Math.Round(pct, 1), 100);
                    CpuUsageText = $"{CpuUsage:F1}%";
                }
                _lastCpuCheck = now;
                _lastCpuTime = currentCpuTime;

                var memBytes = proc.WorkingSet64;
                var memMb = Math.Round(memBytes / (1024.0 * 1024.0), 1);

                if (_totalSystemMemory > 0)
                {
                    var ramPct = Math.Round(memMb / _totalSystemMemory * 100, 1);
                    RamUsage = Math.Min(ramPct, 100);
                    RamUsageText = $"{ramPct:F0}%";
                    RamDetailText = $"{memMb:F0} MB / {_totalSystemMemory:F0} MB";
                }
                else
                {
                    RamUsage = 0;
                    RamUsageText = $"{memMb:F0} MB";
                    RamDetailText = $"{memMb:F0} MB";
                }
            }
            catch { }
        };
        _monitorTimer.Start();
    }

    private static long GetTotalPhysicalMemoryMb()
    {
        try
        {
            var memStatus = new MemoryStatusEx();
            if (GlobalMemoryStatusEx(memStatus))
                return (long)(memStatus.ullTotalPhys / (1024 * 1024));
        }
        catch { }
        return 16384;
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private class MemoryStatusEx
    {
        public uint dwLength = (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(MemoryStatusEx));
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalMemoryStatusEx([System.Runtime.InteropServices.In, System.Runtime.InteropServices.Out] MemoryStatusEx lpBuffer);

    public void UpdateShieldStatus(bool active, int level)
    {
        ShieldActive = active;
        if (active)
        {
            ShieldStatus = $"ESCUDO ACTIVO - Nivel {level}";
            ShieldLevel = $"Nivel {level}";
            OnPropertyChanged(nameof(ShieldColorBrush));
        }
        else
        {
            ShieldStatus = "Inactivo";
            ShieldLevel = "";
            OnPropertyChanged(nameof(ShieldColorBrush));
        }
    }

    public void UpdateUsbScanStatus(string status)
    {
        UsbScanStatus = status;
    }

    private async Task UpdateDefinitions()
    {
        DefinitionsStatus = "Actualizando bases...";
        try
        {
            var progress = new Progress<string>(msg => DefinitionsStatus = msg);
            var count = await _defService.UpdateDefinitionsAsync(progress);
            DefinitionsStatus = $"Bases actualizadas: {count} amenazas conocidas ({_defService.LastUpdate})";
        }
        catch (Exception ex)
        {
            DefinitionsStatus = $"Error: {ex.Message}";
        }
    }
}
