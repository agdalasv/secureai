using System.Collections.ObjectModel;
using System.Windows.Input;
using Secureia.Models;
using Secureia.Services;

namespace Secureia.ViewModels;

public class SettingsViewModel : ViewModelBase
{
    private readonly ConfigService _configService;
    private readonly TtsService _ttsService;
    private readonly AutoStartService _autoStartService;
    private readonly LogService _logService;
    private readonly ScanEngine _scanEngine;
    private readonly PlusActivationService _plusService;
    private string _selectedVoice;
    private bool _autoStart;
    private bool _voiceEnabled;
    private int _voiceVolume;
    private int _selectedNotifyIndex;
    private string _newExclusion = "";
    private string _plusSerialInput = "";
    private string _plusStatus = "";
    private bool _isPlusActivated;

    public AppConfig Config => _configService.Config;

    public bool AutoStart
    {
        get => _autoStart;
        set
        {
            if (SetProperty(ref _autoStart, value))
                UpdateAutoStart();
        }
    }
    public bool VoiceEnabled { get => _voiceEnabled; set { SetProperty(ref _voiceEnabled, value); _ttsService.SetEnabled(value); } }
    public int VoiceVolume { get => _voiceVolume; set { SetProperty(ref _voiceVolume, value); _ttsService.SetVolume(value); } }
    public string SelectedVoice { get => _selectedVoice; set { SetProperty(ref _selectedVoice, value); _ttsService.SetVoice(value); } }
    public int SelectedNotifyIndex { get => _selectedNotifyIndex; set { SetProperty(ref _selectedNotifyIndex, value); Config.NotificationMode = (NotifyMode)value; } }
    public string NewExclusion { get => _newExclusion; set => SetProperty(ref _newExclusion, value); }
    public string PlusSerialInput { get => _plusSerialInput; set => SetProperty(ref _plusSerialInput, value); }
    public string PlusStatus { get => _plusStatus; set => SetProperty(ref _plusStatus, value); }
    public bool IsPlusActivated { get => _isPlusActivated; set => SetProperty(ref _isPlusActivated, value); }

    public ObservableCollection<string> AvailableVoices { get; } = new();

    public ICommand SaveCommand { get; }
    public ICommand AddExclusionCommand { get; }
    public ICommand RemoveExclusionCommand { get; }
    public ICommand BrowseExclusionCommand { get; }
    public ICommand ActivatePlusCommand { get; }
    public ICommand DeactivatePlusCommand { get; }

    public SettingsViewModel(ConfigService configService, TtsService ttsService,
                             AutoStartService autoStartService, LogService logService,
                             ScanEngine scanEngine, PlusActivationService? plusService = null)
    {
        _configService = configService;
        _ttsService = ttsService;
        _autoStartService = autoStartService;
        _logService = logService;
        _scanEngine = scanEngine;
        _plusService = plusService ?? new PlusActivationService(configService);

        _autoStart = Config.AutoStart;
        _voiceEnabled = Config.VoiceEnabled;
        _voiceVolume = Config.VoiceVolume;
        _selectedVoice = Config.VoiceName;
        _selectedNotifyIndex = (int)Config.NotificationMode;
        _isPlusActivated = _plusService.IsPlusActive;
        _plusStatus = _plusService.IsPlusActive
            ? $"Secure AI Plus activado ({_plusService.GetFormattedKey()})"
            : "No activado";

        foreach (var voice in ttsService.GetAvailableVoices())
            AvailableVoices.Add(voice);

        if (string.IsNullOrEmpty(_selectedVoice) && AvailableVoices.Count > 0)
            _selectedVoice = AvailableVoices[0];

        SaveCommand = new RelayCommand(_ => Save());
        AddExclusionCommand = new RelayCommand(_ => AddExclusion());
        RemoveExclusionCommand = new RelayCommand(param => RemoveExclusion(param as string));
        BrowseExclusionCommand = new RelayCommand(_ => BrowseExclusion());
        ActivatePlusCommand = new RelayCommand(_ => ActivatePlus());
        DeactivatePlusCommand = new RelayCommand(_ => DeactivatePlus());
    }

    private void Save()
    {
        Config.AutoStart = AutoStart;
        Config.VoiceEnabled = VoiceEnabled;
        Config.VoiceVolume = VoiceVolume;
        Config.VoiceName = SelectedVoice;
        Config.NotificationMode = (NotifyMode)SelectedNotifyIndex;
        _configService.Save();
        _logService.Log(new LogEntry
        {
            Event = "Configuración guardada",
            ActionTaken = "Guardar configuración",
            User = Environment.UserName
        });
    }

    private void UpdateAutoStart()
    {
        var exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
        if (string.IsNullOrEmpty(exePath)) return;

        if (AutoStart)
            _autoStartService.Enable(exePath);
        else
            _autoStartService.Disable();

        Config.AutoStart = AutoStart;
        _configService.Save();
    }

    private void AddExclusion()
    {
        if (string.IsNullOrWhiteSpace(NewExclusion)) return;
        if (!Config.Exclusions.Contains(NewExclusion))
            Config.Exclusions.Add(NewExclusion);
        NewExclusion = "";
        OnPropertyChanged(nameof(Config));
    }

    private void RemoveExclusion(string? path)
    {
        if (path != null) Config.Exclusions.Remove(path);
        OnPropertyChanged(nameof(Config));
    }

    private void BrowseExclusion()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Seleccionar archivo para exclusión",
            Filter = "All files (*.*)|*.*"
        };
        if (dialog.ShowDialog() == true)
        {
            NewExclusion = dialog.FileName;
            AddExclusion();
        }
    }

    private void ActivatePlus()
    {
        if (string.IsNullOrWhiteSpace(PlusSerialInput))
        {
            PlusStatus = "Ingrese un código de licencia.";
            return;
        }

        if (_plusService.Activate(PlusSerialInput.Trim()))
        {
            IsPlusActivated = true;
            PlusStatus = $"Secure AI Plus activado correctamente. Por favor, reinicie la aplicación.";
            _logService.Log(new LogEntry
            {
                Event = "Secure AI Plus activado",
                ActionTaken = "Activación Plus",
                User = Environment.UserName
            });
        }
        else
        {
            PlusStatus = "Código de licencia inválido. Verifique e intente nuevamente.";
        }
    }

    private void DeactivatePlus()
    {
        _plusService.Deactivate();
        IsPlusActivated = false;
        PlusStatus = "Secure AI Plus desactivado. Reinicie para aplicar cambios.";
        _logService.Log(new LogEntry
        {
            Event = "Secure AI Plus desactivado",
            ActionTaken = "Desactivación Plus",
            User = Environment.UserName
        });
    }
}
