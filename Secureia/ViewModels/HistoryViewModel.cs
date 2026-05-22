using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using Secureia.Models;
using Secureia.Services;

namespace Secureia.ViewModels;

public class HistoryViewModel : ViewModelBase
{
    private readonly LogService _logService;
    private DefenseShieldAI? _shield;
    private WindowsDefenderService? _defenderService;
    private bool _isPlusActive;

    public ObservableCollection<LogEntry> Logs { get; } = new();

    public ICommand ClearCommand { get; }
    public ICommand ExportCommand { get; }
    public ICommand RefreshCommand { get; }
    public ICommand SaveToDocumentsCommand { get; }
    public ICommand OpenAppFolderCommand { get; }
    public ICommand OpenThreatDetailCommand { get; }

    public HistoryViewModel(LogService logService)
    {
        _logService = logService;

        ClearCommand = new RelayCommand(_ => Clear());
        ExportCommand = new RelayCommand(_ => Export());
        RefreshCommand = new RelayCommand(_ => LoadLogs());
        SaveToDocumentsCommand = new RelayCommand(_ => SaveToDocuments());
        OpenAppFolderCommand = new RelayCommand(_ => OpenAppFolder());
        OpenThreatDetailCommand = new RelayCommand(param => OpenThreatDetail(param as LogEntry));
    }

    public void SetServices(DefenseShieldAI? shield, WindowsDefenderService? defenderService, bool isPlusActive)
    {
        _shield = shield;
        _defenderService = defenderService;
        _isPlusActive = isPlusActive;
    }

    public void LoadLogs()
    {
        Logs.Clear();
        foreach (var entry in _logService.GetLogs())
            Logs.Add(entry);
    }

    private void OpenThreatDetail(LogEntry? entry)
    {
        if (entry == null || !entry.IsNetworkThreat) return;
        if (!_isPlusActive) return;

        var window = new Views.ThreatDetailWindow(entry, _logService, _shield, _defenderService);
        window.Owner = Application.Current.MainWindow;
        window.ShowDialog();

        if (window.IsResolved)
        {
            _logService.ClearLogs();
            LoadLogs();
        }
    }

    private void Clear()
    {
        _logService.ClearLogs();
        Logs.Clear();
    }

    private void Export()
    {
        var dialog = new SaveFileDialog
        {
            Filter = "JSON files (*.json)|*.json|Text files (*.txt)|*.txt|All files (*.*)|*.*",
            FileName = $"Secureia_Export_{DateTime.Now:yyyyMMdd_HHmmss}"
        };

        if (dialog.ShowDialog() == true)
            _logService.ExportLogs(dialog.FileName);
    }

    private void SaveToDocuments()
    {
        try
        {
            var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            var path = Path.Combine(docs, $"SecureAI_Log_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            _logService.ExportLogs(path);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe", $"/select,\"{path}\"")
            {
                UseShellExecute = true
            });
        }
        catch { }
    }

    private void OpenAppFolder()
    {
        try
        {
            var dir = AppDomain.CurrentDomain.BaseDirectory;
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe", dir)
            {
                UseShellExecute = true
            });
        }
        catch { }
    }
}
