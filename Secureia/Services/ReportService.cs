using System.IO;
using System.Text.Json;
using Secureia.Models;

namespace Secureia.Services;

public class ReportService
{
    private readonly string _reportsDir;

    public ReportService(ConfigService configService)
    {
        var baseDir = configService.ResolvePath(configService.Config.LogPath);
        _reportsDir = Path.Combine(Path.GetDirectoryName(baseDir) ?? AppDomain.CurrentDomain.BaseDirectory, "Reports");
        Directory.CreateDirectory(_reportsDir);
    }

    public string ReportsDir => _reportsDir;

    public void GenerateReport(ThreatReport report)
    {
        report.ResolvedAt = DateTime.Now;
        var fileName = $"report_{report.DetectedAt:yyyyMMdd_HHmmss}_{report.ReportId}.json";
        var filePath = Path.Combine(_reportsDir, fileName);
        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(filePath, json);
    }

    public List<ThreatReport> GetReports()
    {
        var reports = new List<ThreatReport>();
        if (!Directory.Exists(_reportsDir)) return reports;

        foreach (var file in Directory.GetFiles(_reportsDir, "report_*.json").OrderByDescending(f => f))
        {
            try
            {
                var json = File.ReadAllText(file);
                var report = JsonSerializer.Deserialize<ThreatReport>(json);
                if (report != null)
                    reports.Add(report);
            }
            catch { }
        }
        return reports;
    }

    public string GetFormattedReport(ThreatReport report)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("==============================================");
        sb.AppendLine("  INFORME DE AMENAZA - SECURE AI PLUS");
        sb.AppendLine("==============================================");
        sb.AppendLine($"  ID:                {report.ReportId}");
        sb.AppendLine($"  Detectado:         {report.DetectedAt:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"  Resuelto:          {report.ResolvedAt:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"  Tipo:              {report.ThreatType}");
        sb.AppendLine($"  Nivel:             {report.Level}");
        sb.AppendLine($"  Descripción:       {report.Description}");
        sb.AppendLine($"  IP Origen:         {report.SourceIp ?? "N/A"}");
        sb.AppendLine($"  Puerto Origen:     {(report.SourcePort > 0 ? report.SourcePort.ToString() : "N/A")}");
        sb.AppendLine($"  IP Destino:        {report.DestinationIp ?? "N/A"}");
        sb.AppendLine($"  Puerto Destino:    {(report.DestinationPort > 0 ? report.DestinationPort.ToString() : "N/A")}");
        sb.AppendLine($"  Acción:            {report.ActionTaken}");
        sb.AppendLine($"  Resuelto por:      {report.ResolvedBy}");
        sb.AppendLine("==============================================");
        return sb.ToString();
    }
}