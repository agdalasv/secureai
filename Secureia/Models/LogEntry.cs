namespace Secureia.Models;

public class LogEntry
{
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public string Event { get; set; } = "";
    public string FilePath { get; set; } = "";
    public string ActionTaken { get; set; } = "";
    public string User { get; set; } = Environment.UserName;
    public string? Description { get; set; }
    public string? ThreatType { get; set; }
    public string? SourceIp { get; set; }
    public int SourcePort { get; set; }
    public string? DestinationIp { get; set; }
    public int DestinationPort { get; set; }
    public ThreatLevel Level { get; set; } = ThreatLevel.Low;
    public bool IsNetworkThreat => !string.IsNullOrEmpty(ThreatType);
    public bool IsResolved { get; set; }
}
