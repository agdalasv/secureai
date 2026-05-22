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
    private ReportService? _reportService;

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

            ExpertMalwareAI? expertMalware = null;
            ExpertNetworkAI? expertNetwork = null;
            UsbScanner? usbScanner = null;
            DefenseShieldAI? shield = null;

            if (_plusService.IsPlusActive)
            {
                shield = new DefenseShieldAI(ttsService, _logService, expertMalware, expertNetwork);
                expertMalware = new ExpertMalwareAI(ttsService, _logService, _defService, threatDb);
                expertNetwork = new ExpertNetworkAI(ttsService, _logService, threatDb, shield, _reportService);
                usbScanner = new UsbScanner(scanEngine, ttsService, _logService, expertMalware);
                _expertMalware = expertMalware;
                _expertNetwork = expertNetwork;
            }

            var monitor = new BackgroundMonitor(ttsService, _logService, _defService, threatDb,
                                                 _plusService, expertMalware, expertNetwork,
                                                 usbScanner, shield, scanEngine);
            monitor.Start();

            EnsureAutoStart(autoStartService);

            SystemEvents.SessionEnding += OnSessionEnding;

            _ = InitializeDefenderIntegrationSafeAsync();

            ttsService.SpeakStartup();

            var mainViewModel = new MainViewModel(
                scanEngine, ttsService, _configService,
                _logService, quarantineService, _cleanupService,
                autoStartService, _defService, _defenderService,
                _plusService);

            mainViewModel.History.SetServices(shield, _defenderService, _plusService.IsPlusActive);

            monitor.ShieldStatusChanged += (msg, level) =>
            {
                Dispatcher.Invoke(() =>
                    mainViewModel.Dashboard.UpdateShieldStatus(level > 0, level));
            };

            monitor.UsbScanStatus += status =>
            {
                Dispatcher.Invoke(() =>
                    mainViewModel.Dashboard.UpdateUsbScanStatus(status));
            };

            monitor.Alert += msg =>
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

    private void EnsureAutoStart(AutoStartService autoStartService)
    {
        if (!_configService!.Config.AutoStart) return;
        if (autoStartService.IsEnabled()) return;

        var exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
        if (!string.IsNullOrEmpty(exePath))
        {
            autoStartService.Enable(exePath);
            _logService?.Log(new LogEntry
            {
                Event = "Auto-inicio configurado al arrancar el sistema",
                ActionTaken = "Registro RUN",
                User = Environment.UserName
            });
        }
    }

    private void OnSessionEnding(object? sender, SessionEndingEventArgs e)
    {
        if (_configService?.Config.CleanupBeforeShutdown == true && _cleanupService != null)
        {
            var result = _cleanupService.RunCleanupSync();
            _logService?.Log(new LogEntry
            {
                Event = $"Limpieza pre-apagado: {result.FormattedFreed} liberados",
                ActionTaken = "Limpieza automática",
                User = Environment.UserName
            });
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        SystemEvents.SessionEnding -= OnSessionEnding;
        _defService?.Dispose();
        base.OnExit(e);
    }
}
