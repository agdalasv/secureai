using System.IO;
using System.Text.Json;
using Secureia.Models;

namespace Secureia.Services;

public class ConfigService
{
    private readonly string _configPath;

    public AppConfig Config { get; private set; } = new();

    public ConfigService()
    {
        var appDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Secureia");
        Directory.CreateDirectory(appDir);
        _configPath = Path.Combine(appDir, "config.json");
        Load();
    }

    public void Load()
    {
        if (!File.Exists(_configPath)) return;
        try
        {
            var json = File.ReadAllText(_configPath);
            Config = JsonSerializer.Deserialize<AppConfig>(json) ?? new AppConfig();
        }
        catch
        {
            Config = new AppConfig();
        }
    }

    public void Save()
    {
        var json = JsonSerializer.Serialize(Config, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_configPath, json);
    }

    public string ResolvePath(string path)
    {
        return Environment.ExpandEnvironmentVariables(path);
    }
}
