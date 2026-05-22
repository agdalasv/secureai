using System.Collections.ObjectModel;
using System.Windows.Input;
using Secureia.Models;
using Secureia.Services;

namespace Secureia.ViewModels;

public class MainViewModel : ViewModelBase
{
    private string _currentView = "Dashboard";
    private bool _isPlusActive;
    private readonly PlusActivationService _plusService;
    private readonly TtsService _tts;
    private readonly LogService _logService;
    private readonly ConfigService _configService;
    private readonly AutoStartService _autoStartService;
    private readonly WindowsDefenderService _defenderService;

    public ConfigService ConfigService => _configService;
    public TtsService TtsService => _tts;
    public WindowsDefenderService DefenderService => _defenderService;
    public PlusActivationService PlusService => _plusService;
    public DashboardViewModel Dashboard { get; }
    public ScanViewModel Scan { get; }
    public HistoryViewModel History { get; }
    public QuarantineViewModel Quarantine { get; }
    public SettingsViewModel Settings { get; }

    public bool IsPlusActive
    {
        get => _isPlusActive;
        set => SetProperty(ref _isPlusActive, value);
    }

    public string CurrentView
    {
        get => _currentView;
        set => SetProperty(ref _currentView, value);
    }

    public ICommand NavigateCommand { get; }
    public ICommand ShowDashboardCommand { get; }
    public ICommand ShowScanCommand { get; }
    public ICommand ShowHistoryCommand { get; }
    public ICommand ShowQuarantineCommand { get; }
    public ICommand ShowSettingsCommand { get; }
    public ICommand DisableDefenderCommand { get; }

    public MainViewModel(ScanEngine scanEngine, TtsService tts, ConfigService configService,
                         LogService logService, QuarantineService quarantineService,
                         CleanupService cleanupService, AutoStartService autoStartService,
                         DefinitionService defService, WindowsDefenderService defenderService,
                         PlusActivationService plusService)
    {
        _tts = tts;
        _logService = logService;
        _configService = configService;
        _autoStartService = autoStartService;
        _defenderService = defenderService;
        _plusService = plusService;
        _isPlusActive = plusService.IsPlusActive;

        Dashboard = new DashboardViewModel(scanEngine, defService, defenderService);
        Scan = new ScanViewModel(scanEngine, quarantineService, logService, tts);
        History = new HistoryViewModel(logService);
        Quarantine = new QuarantineViewModel(quarantineService, logService);
        Settings = new SettingsViewModel(configService, tts, autoStartService, logService, scanEngine, plusService);

        NavigateCommand = new RelayCommand(param => Navigate(param?.ToString() ?? "Dashboard"));
        ShowDashboardCommand = new RelayCommand(_ => CurrentView = "Dashboard");
        ShowScanCommand = new RelayCommand(_ => CurrentView = "Scan");
        ShowHistoryCommand = new RelayCommand(_ => { History.LoadLogs(); CurrentView = "History"; });
        ShowQuarantineCommand = new RelayCommand(_ => { Quarantine.LoadItems(); CurrentView = "Quarantine"; });
        ShowSettingsCommand = new RelayCommand(_ => CurrentView = "Settings");
        DisableDefenderCommand = new RelayCommand(async _ => await DisableDefender());
    }

    private void Navigate(string view) => CurrentView = view;

    private async Task DisableDefender()
    {
        Dashboard.DefenderStatus = "Desactivando Defender...";
        Dashboard.DefenderColor = "#FFB74D";

        try
        {
            var exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
            if (!string.IsNullOrEmpty(exePath))
            {
                var exeDir = System.IO.Path.GetDirectoryName(exePath);
                if (!string.IsNullOrEmpty(exeDir))
                    await _defenderService.AddExclusionAsync(exeDir);
            }

            var ok = await _defenderService.DisableDefenderAsync();
            await Dashboard.RefreshDefenderStatus();

            if (ok)
            {
                _tts?.Speak("Windows Defender ha sido desactivado. Secure AI ahora protege su sistema.");
                _logService?.Log(new LogEntry
                {
                    Event = "Windows Defender desactivado por Secure AI",
                    ActionTaken = "Desactivación de Defender",
                    User = Environment.UserName
                });
            }
            else
            {
                Dashboard.DefenderStatus = "No se pudo desactivar. Desactive 'Protección contra manipulaciones' en Seguridad de Windows e intente de nuevo.";
            }
        }
        catch
        {
            Dashboard.DefenderStatus = "Error al desactivar Defender";
        }
    }
}
