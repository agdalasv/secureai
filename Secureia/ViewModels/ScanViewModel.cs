using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows.Input;
using Secureia.Models;
using Secureia.Services;

namespace Secureia.ViewModels;

public class ScanViewModel : ViewModelBase
{
    private readonly ScanEngine _scanEngine;
    private readonly QuarantineService _quarantineService;
    private readonly LogService _logService;
    private readonly TtsService _ttsService;
    private string _scanPath;
    private string _status = "Listo para escanear";
    private int _progress;
    private int _total;
    private bool _isScanning;
    private int _selectedTab;

    public string ScanPath
    {
        get => _scanPath;
        set => SetProperty(ref _scanPath, value);
    }
    public string Status { get => _status; set => SetProperty(ref _status, value); }
    public int Progress { get => _progress; set => SetProperty(ref _progress, value); }
    public int Total { get => _total; set => SetProperty(ref _total, value); }
    public bool IsScanning { get => _isScanning; set => SetProperty(ref _isScanning, value); }
    public int SelectedTab { get => _selectedTab; set => SetProperty(ref _selectedTab, value); }

    public ObservableCollection<ScanResult> Results { get; } = new();

    public ICommand ScanCommand { get; }
    public ICommand CancelCommand { get; }
    public ICommand QuarantineCommand { get; }
    public ICommand DeleteCommand { get; }
    public ICommand IgnoreCommand { get; }
    public ICommand ScanQuickCommand { get; }
    public ICommand ScanFullCommand { get; }
    public ICommand ScanCustomCommand { get; }
    public ICommand OpenFolderCommand { get; }

    public ScanViewModel(ScanEngine scanEngine, QuarantineService quarantineService,
                         LogService logService, TtsService ttsService)
    {
        _scanEngine = scanEngine;
        _quarantineService = quarantineService;
        _logService = logService;
        _ttsService = ttsService;
        _scanPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads";

        ScanCommand = new RelayCommand(async _ => await StartScan());
        CancelCommand = new RelayCommand(_ => CancelScan());
        QuarantineCommand = new RelayCommand(param => QuarantineFile(param as ScanResult));
        DeleteCommand = new RelayCommand(param => DeleteFile(param as ScanResult));
        IgnoreCommand = new RelayCommand(param => IgnoreFile(param as ScanResult));
        ScanQuickCommand = new RelayCommand(async _ => { ScanPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads"; await StartScan(); });
        ScanFullCommand = new RelayCommand(async _ => { ScanPath = "C:\\Users"; await StartScan(); });
        ScanCustomCommand = new RelayCommand(_ => { });
        OpenFolderCommand = new RelayCommand(param => OpenFolder(param as ScanResult));

        _scanEngine.ProgressChanged += (p, t) => { Progress = p; Total = t; };
        _scanEngine.StatusChanged += s => Status = s;
        _scanEngine.ThreatDetected += r =>
        {
            App.Current?.Dispatcher?.Invoke(() => Results.Insert(0, r));
        };
    }

    private async Task StartScan()
    {
        if (IsScanning) return;
        IsScanning = true;
        Results.Clear();
        Progress = 0;
        Total = 0;
        Status = "Iniciando escaneo...";

        if (!Directory.Exists(ScanPath))
        {
            Status = "La ruta no existe.";
            IsScanning = false;
            return;
        }

        var results = await _scanEngine.ScanDirectoryAsync(ScanPath);
        IsScanning = _scanEngine.IsScanning;

        if (results.Count == 0)
            Status = "Escaneo completado. No se encontraron amenazas.";
        else
            Status = $"Escaneo completado. {results.Count} amenaza(s) encontrada(s).";
    }

    private void CancelScan()
    {
        _scanEngine.Cancel();
        Status = "Escaneo cancelado por el usuario.";
        IsScanning = false;
    }

    private void QuarantineFile(ScanResult? result)
    {
        if (result == null) return;
        _quarantineService.Quarantine(result);
        result.Action = ScanAction.Quarantine;
        _logService.Log(new LogEntry
        {
            Event = "Archivo en cuarentena",
            FilePath = result.FilePath,
            ActionTaken = "Cuarentena",
            User = Environment.UserName
        });
        _ttsService.SpeakThreatRemoved();
        Results.Remove(result);
    }

    private void DeleteFile(ScanResult? result)
    {
        if (result == null) return;
        try
        {
            if (File.Exists(result.FilePath)) File.Delete(result.FilePath);
            result.Action = ScanAction.Delete;
            _logService.Log(new LogEntry
            {
                Event = "Archivo eliminado",
                FilePath = result.FilePath,
                ActionTaken = "Eliminar",
                User = Environment.UserName
            });
            _ttsService.SpeakThreatRemoved();
            Results.Remove(result);
        }
        catch (Exception ex)
        {
            Status = $"Error al eliminar: {ex.Message}";
        }
    }

    private void IgnoreFile(ScanResult? result)
    {
        if (result == null) return;
        result.Action = ScanAction.Ignore;
        _logService.Log(new LogEntry
        {
            Event = "Amenaza ignorada",
            FilePath = result.FilePath,
            ActionTaken = "Ignorar",
            User = Environment.UserName
        });
        Results.Remove(result);
    }

    private void OpenFolder(ScanResult? result)
    {
        if (result?.FilePath == null) return;
        try
        {
            var dir = Path.GetDirectoryName(result.FilePath);
            if (dir != null && Directory.Exists(dir))
            {
                var psi = new ProcessStartInfo("explorer.exe", $"/select,\"{result.FilePath}\"")
                {
                    UseShellExecute = true
                };
                Process.Start(psi);
            }
        }
        catch { }
    }
}
