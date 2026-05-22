using System.Diagnostics;
using System.IO;
using System.Windows;
using Microsoft.Win32;
using Secureia.Models;
using Secureia.Services;
using Secureia.ViewModels;

namespace Secureia;

public partial class App : Application
{
    private CleanupService? _cleanupService;
    private LogService? _logService;
    private ConfigService? _configService;
    private DefinitionService? _defService;
    private WindowsDefenderService? _defenderService;
    private PlusActivationService? _plusService;
    private ExpertMalwareAI? _expertMalware;
    private ExpertNetworkAI? _expertNetwork;
    private ShadowHelperAI? _shadowHelper;
    private ReportService? _reportService;
    private BackgroundMonitor? _monitor;

    public WindowsDefenderService? DefenderService => _defenderService;
    public PlusActivationService? PlusService => _plusService;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        DispatcherUnhandledException += (_, args) =>
        {
            MessageBox.Show($"Error inesperado: {args.Exception.Message}",
                "Secureia - Error", MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };

        try
        {
            _configService = new ConfigService();
            _defService = new DefinitionService();
            var threatDb = new ThreatDatabase();
            var scanEngine = new ScanEngine(_defService, threatDb);
            var ttsService = new TtsService();
            _logService = new LogService(_configService);
            var quarantineService = new QuarantineService(_configService);
            _cleanupService = new CleanupService();
            var autoStartService = new AutoStartService();
            _defenderService = new WindowsDefenderService();
            _plusService = new PlusActivationService(_configService);
            _reportService = new ReportService(_configService);

            // Verificar que el hardware sigue siendo el mismo (ata al serial a una sola PC)
            var isPlusActivated = _plusService.IsPlusActive;
            if (isPlusActivated)
                isPlusActivated = _plusService.VerifyHardwareBinding();

            ExpertMalwareAI? expertMalware = null;
            ExpertNetworkAI? expertNetwork = null;
            UsbScanner? usbScanner = null;
            DefenseShieldAI? shield = null;
            var deepAnalyzer = new DeepAnalyzer(_defService, threatDb);

            if (isPlusActivated)
            {
                shield = new DefenseShieldAI(ttsService, _logService, expertMalware, expertNetwork);
                expertMalware = new ExpertMalwareAI(ttsService, _logService, _defService, threatDb);
                expertNetwork = new ExpertNetworkAI(ttsService, _logService, threatDb, shield, _reportService);
                usbScanner = new UsbScanner(scanEngine, ttsService, _logService, expertMalware);
                _shadowHelper = new ShadowHelperAI(ttsService, _logService, _defService, threatDb, deepAnalyzer);
                _expertMalware = expertMalware;
                _expertNetwork = expertNetwork;
            }

            if (isPlusActivated != _plusService.IsPlusActive)
            {
                _logService?.Log(new LogEntry
                {
                    Event = isPlusActivated
                        ? "Secure AI Plus activado - AIs expertas desplegadas"
                        : "Secure AI Plus desactivado por cambio de hardware - contacte a agdala.sv@gmail.com para reactivar",
                    ActionTaken = "Verificación de licencia",
                    User = Environment.UserName
                });
            }

            _monitor = new BackgroundMonitor(ttsService, _logService, _defService, threatDb,
                                             _plusService, expertMalware, expertNetwork,
                                             usbScanner, shield, scanEngine,
                                             _shadowHelper, _cleanupService);
            _monitor.Start();

            // Auto-arranque siempre activo - la Main AI debe proteger desde el inicio
            ForceAutoStart(autoStartService);

            SystemEvents.SessionEnding += OnSessionEnding;

            _ = InitializeDefenderIntegrationSafeAsync();

            ttsService.SpeakStartup();

            var mainViewModel = new MainViewModel(
                scanEngine, ttsService, _configService!,
                _logService!, quarantineService!, _cleanupService!,
                autoStartService, _defService!, _defenderService!,
                _plusService!);

            mainViewModel.History.SetServices(shield, _defenderService, _plusService.IsPlusActive);

            _monitor.ShieldStatusChanged += (msg, level) =>
            {
                Dispatcher.Invoke(() =>
                    mainViewModel.Dashboard.UpdateShieldStatus(level > 0, level));
            };

            _monitor.UsbScanStatus += status =>
            {
                Dispatcher.Invoke(() =>
                    mainViewModel.Dashboard.UpdateUsbScanStatus(status));
            };

            _monitor.Alert += msg =>
            {
                Dispatcher.Invoke(() =>
                    mainViewModel.Dashboard.ScanStatus = msg);
            };

            var mainWindow = new MainWindow(mainViewModel);
            mainWindow.Show();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error al iniciar Secureia:\n{ex.Message}",
                "Secureia - Error de inicio", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown();
        }
    }

    private async Task InitializeDefenderIntegrationSafeAsync()
    {
        if (_defenderService == null || _configService == null) return;

        try
        {
            // Solo agrega exclusiones para evitar falsos positivos, sin desactivar Defender
            var exePath = Process.GetCurrentProcess().MainModule?.FileName;
            if (!string.IsNullOrEmpty(exePath))
            {
                var exeDir = Path.GetDirectoryName(exePath);
                if (!string.IsNullOrEmpty(exeDir))
                    await _defenderService.AddExclusionAsync(exeDir);
            }

            var localAppData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Secureia");
            if (Directory.Exists(localAppData))
                await _defenderService.AddExclusionAsync(localAppData);

            _logService?.Log(new LogEntry
            {
                Event = "Secure AI iniciado - exclusiones agregadas a Defender",
                ActionTaken = "Inicialización segura",
                User = Environment.UserName
            });
        }
        catch { }
    }

    private void ForceAutoStart(AutoStartService autoStartService)
    {
        try
        {
            var exePath = Process.GetCurrentProcess().MainModule?.FileName;
            if (!string.IsNullOrEmpty(exePath))
            {
                if (!autoStartService.IsEnabled())
                {
                    autoStartService.Enable(exePath);
                    _logService?.Log(new LogEntry
                    {
                        Event = "Auto-inicio configurado - Main AI siempre protege desde el arranque",
                        ActionTaken = "Registro RUN forzado",
                        User = Environment.UserName
                    });
                }

                _configService!.Config.AutoStart = true;
                _configService.Save();
            }
        }
        catch { }
    }

    private void OnSessionEnding(object? sender, SessionEndingEventArgs e)
    {
        // La Main AI siempre ejecuta limpieza profunda al apagar/reiniciar
        _monitor?.PrepareForShutdown();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        SystemEvents.SessionEnding -= OnSessionEnding;
        _monitor?.PrepareForShutdown();
        _monitor?.Dispose();
        _shadowHelper?.Dispose();
        _defService?.Dispose();
        base.OnExit(e);
    }
}
