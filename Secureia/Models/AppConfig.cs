namespace Secureia.Models;

public class AppConfig
{
    public bool AutoStart { get; set; } = true;
    public bool DesktopShortcut { get; set; } = true;
    public bool StartMenuShortcut { get; set; } = true;
    public string LogPath { get; set; } = "%LOCALAPPDATA%\\Secureia\\Logs";
    public string QuarantinePath { get; set; } = "%LOCALAPPDATA%\\Secureia\\Quarantine";
    public NotifyMode NotificationMode { get; set; } = NotifyMode.Normal;
    public string VoiceName { get; set; } = "";
    public int VoiceVolume { get; set; } = 80;
    public bool VoiceEnabled { get; set; } = true;
    public bool ProtectAll { get; set; } = true;
    public bool ProtectSystem { get; set; } = true;
    public bool ProtectNetwork { get; set; } = true;
    public bool ProtectMalware { get; set; } = true;
    public bool ProtectHarmfulApps { get; set; } = true;
    public ScanSchedule Schedule { get; set; } = new();
    public List<string> Exclusions { get; set; } = new();
    public bool CleanupBeforeShutdown { get; set; } = true;
    public bool PlusActivated { get; set; } = false;
    public string? PlusSerialKey { get; set; }
    public DateTime? PlusActivationDate { get; set; }
}

public class ScanSchedule
{
    public bool Enabled { get; set; } = false;
    public ScanFrequency Frequency { get; set; } = ScanFrequency.Daily;
    public TimeSpan Time { get; set; } = new(14, 0, 0);
}

public enum NotifyMode
{
    Silent,
    Normal,
    Critical
}

public enum ScanFrequency
{
    Daily,
    Weekly,
    Monthly
}
