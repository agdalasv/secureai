using System.IO;
using System.Text.Json;
using Secureia.Models;

namespace Secureia.Services;

public class QuarantineService
{
    private readonly string _quarantineDir;
    private readonly string _indexFile;
    private List<QuarantineItem> _items;
    private readonly object _lock = new();

    public QuarantineService(ConfigService configService)
    {
        _quarantineDir = configService.ResolvePath(configService.Config.QuarantinePath);
        Directory.CreateDirectory(_quarantineDir);
        _indexFile = Path.Combine(_quarantineDir, "index.json");
        _items = LoadIndex();
    }

    public IReadOnlyList<QuarantineItem> Items => _items.AsReadOnly();

    public void Quarantine(ScanResult result)
    {
        lock (_lock)
        {
            var uniqueName = $"{Guid.NewGuid()}_{Path.GetFileName(result.FilePath)}";
            var destPath = Path.Combine(_quarantineDir, uniqueName);

            try
            {
                File.Move(result.FilePath, destPath);
            }
            catch
            {
                File.Copy(result.FilePath, destPath, true);
            }

            var item = new QuarantineItem
            {
                OriginalPath = result.FilePath,
                QuarantinePath = destPath,
                ThreatName = result.ThreatName,
                Level = result.Level,
                QuarantinedAt = DateTime.Now,
                FileSize = new FileInfo(destPath).Length
            };

            _items.Add(item);
            SaveIndex();
        }
    }

    public void Restore(QuarantineItem item)
    {
        lock (_lock)
        {
            if (!File.Exists(item.QuarantinePath)) return;
            var dir = Path.GetDirectoryName(item.OriginalPath);
            if (dir != null) Directory.CreateDirectory(dir);
            File.Move(item.QuarantinePath, item.OriginalPath);
            _items.Remove(item);
            SaveIndex();
        }
    }

    public void Delete(QuarantineItem item)
    {
        lock (_lock)
        {
            if (File.Exists(item.QuarantinePath))
                File.Delete(item.QuarantinePath);
            _items.Remove(item);
            SaveIndex();
        }
    }

    public void DeleteAll()
    {
        lock (_lock)
        {
            foreach (var item in _items.ToList())
            {
                if (File.Exists(item.QuarantinePath))
                    File.Delete(item.QuarantinePath);
            }
            _items.Clear();
            SaveIndex();
        }
    }

    private List<QuarantineItem> LoadIndex()
    {
        if (!File.Exists(_indexFile)) return new();
        try
        {
            var json = File.ReadAllText(_indexFile);
            return JsonSerializer.Deserialize<List<QuarantineItem>>(json) ?? new();
        }
        catch { return new(); }
    }

    private void SaveIndex()
    {
        var json = JsonSerializer.Serialize(_items, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_indexFile, json);
    }
}
