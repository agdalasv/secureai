namespace Secureia.Models;

public class ThreatReport
{
    public string ReportId { get; set; } = Guid.NewGuid().ToString("N")[..12];
    public DateTime DetectedAt { get; set; } = DateTime.Now;
    public DateTime? ResolvedAt { get; set; }
    public string ThreatType { get; set; } = "";
    public string Description { get; set; } = "";
    public string? SourceIp { get; set; }
    public int SourcePort { get; set; }
    public string? DestinationIp { get; set; }
    public int DestinationPort { get; set; }
    public ThreatLevel Level { get; set; }
    public string ActionTaken { get; set; } = "";
    public string ResolvedBy { get; set; } = "Secure AI Plus - AI Experta en Red";
    public string RawAlert { get; set; } = "";
}