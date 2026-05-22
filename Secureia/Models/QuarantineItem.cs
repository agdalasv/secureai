namespace Secureia.Models;

public class QuarantineItem
{
    public string OriginalPath { get; set; } = "";
    public string QuarantinePath { get; set; } = "";
    public string ThreatName { get; set; } = "";
    public ThreatLevel Level { get; set; } = ThreatLevel.Low;
    public DateTime QuarantinedAt { get; set; } = DateTime.Now;
    public long FileSize { get; set; }
}
