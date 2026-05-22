using System.IO;
using System.Text.Json;
using Secureia.Models;

namespace Secureia.Services;

public class LogService
{
    private readonly string _logDir;
    private readonly object _lock = new();

    public LogService(ConfigService configService)
    {
        _logDir = configService.ResolvePath(configService.Config.LogPath);
        Directory.CreateDirectory(_logDir);
    }

    public string LogDir => _logDir;

    public void Log(LogEntry entry)
    {
        lock (_lock)
        {
            var timestamp = entry.Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
            var txtLine = $"[{timestamp}] | {entry.Event} | Archivo: {entry.FilePath} | Acción: {entry.ActionTaken} | Usuario: {entry.User}";
            var txtPath = Path.Combine(_logDir, $"Secureia_{entry.Timestamp:yyyy-MM}.txt");
            File.AppendAllText(txtPath, txtLine + Environment.NewLine);

            var jsonPath = Path.Combine(_logDir, $"Secureia_{entry.Timestamp:yyyy-MM}.json");
            var jsonLine = JsonSerializer.Serialize(entry) + Environment.NewLine;
            File.AppendAllText(jsonPath, jsonLine);
        }
    }

    public List<LogEntry> GetLogs()
    {
        var logs = new List<LogEntry>();
        if (!Directory.Exists(_logDir)) return logs;

        foreach (var file in Directory.GetFiles(_logDir, "Secureia_*.json").OrderByDescending(f => f))
        {
            try
            {
                var lines = File.ReadAllLines(file);
                foreach (var line in lines)
                {
                    if (!string.IsNullOrWhiteSpace(line))
                        logs.Add(JsonSerializer.Deserialize<LogEntry>(line)!);
                }
            }
            catch { }
        }
        return logs;
    }

    public void ClearLogs()
    {
        lock (_lock)
        {
            foreach (var file in Directory.GetFiles(_logDir, "Secureia_*"))
                File.Delete(file);
        }
    }

    public void ExportLogs(string destinationPath)
    {
        var logs = GetLogs();
        if (destinationPath.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
        {
            var lines = new List<string>
            {
                $"=== Secure AI - Registro de Actividad ===",
                $"Generado: {DateTime.Now:yyyy-MM-dd HH:mm:ss}",
                $"Total de eventos: {logs.Count}",
                ""
            };
            foreach (var log in logs)
            {
                lines.Add($"[{log.Timestamp:yyyy-MM-dd HH:mm:ss}] {log.Event}");
                if (!string.IsNullOrEmpty(log.FilePath))
                    lines.Add($"  Archivo: {log.FilePath}");
                if (!string.IsNullOrEmpty(log.ActionTaken))
                    lines.Add($"  Acción: {log.ActionTaken}");
                if (!string.IsNullOrEmpty(log.User))
                    lines.Add($"  Usuario: {log.User}");
                lines.Add("");
            }
            File.WriteAllLines(destinationPath, lines);
        }
        else
        {
            var json = JsonSerializer.Serialize(logs, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(destinationPath, json);
        }
    }
}
