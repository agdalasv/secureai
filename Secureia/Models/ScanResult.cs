namespace Secureia.Models;

public class ScanResult
{
    public string FilePath { get; set; } = "";
    public string FileName => System.IO.Path.GetFileName(FilePath);
    public string ThreatName { get; set; } = "";
    public ThreatLevel Level { get; set; } = ThreatLevel.Low;
    public string Description { get; set; } = "";
    public ScanAction Action { get; set; } = ScanAction.Pending;
    public DateTime DetectedAt { get; set; } = DateTime.Now;
}

public enum ThreatLevel
{
    Low,
    Medium,
    High,
    Critical
}

public enum ScanAction
{
    Pending,
    Quarantine,
    Delete,
    Ignore
}
