using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Secureia.Services;

public class DefinitionService : IDisposable
{
    private readonly string _defDir;
    private static readonly string[] DefinitionSources = {
        // === Malware hashes SHA256 ===
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware_hash.txt",
        "https://raw.githubusercontent.com/PolitoInc/malware-analysis/main/malware_hashes.txt",
        "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/sha256.txt",
        "https://raw.githubusercontent.com/amitambekar510/Malicious-Hash-Threat-List/main/sha256.txt",
        "https://botvrij.eu/data/ioclist.sha256.raw",
        "https://raw.githubusercontent.com/fabriziosalmi/ransomware-lists/main/sha256.txt",
    };

    private Timer? _updateTimer;
    private readonly HttpClient _client;
    private bool _updating;

    public string LastUpdate { get; private set; } = "Nunca";
    public int KnownThreats { get; private set; }
    public string UpdateStatus { get; private set; } = "Esperando actualización";
    public bool IsUpdating => _updating;

    public event Action<string, int>? DefinitionsUpdated;
    public event Action<string>? UpdateError;

    public DefinitionService()
    {
        _defDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "definitions");
        Directory.CreateDirectory(_defDir);

        _client = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        _client.DefaultRequestHeaders.UserAgent.ParseAdd("SecureAI/1.0");

        LoadMetadata();
        StartAutoUpdate();
    }

    private void StartAutoUpdate()
    {
        var interval = TimeSpan.FromHours(1);
        _updateTimer = new Timer(async _ =>
        {
            if (_updating) return;
            try
            {
                await UpdateDefinitionsAsync();
            }
            catch { }
        }, null, TimeSpan.FromSeconds(30), interval);
    }

    public async Task<int> UpdateDefinitionsAsync(IProgress<string>? progress = null)
    {
        if (_updating)
        {
            progress?.Report("Ya se está actualizando...");
            return KnownThreats;
        }

        _updating = true;
        UpdateStatus = "Actualizando...";
        progress?.Report("Iniciando actualización de bases de datos...");

        var knownHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var url in DefinitionSources)
        {
            try
            {
                progress?.Report($"Descargando definiciones desde {url}...");
                UpdateStatus = $"Descargando: {url}";

                var content = await _client.GetStringAsync(url);

                var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith('#') || trimmed.Length < 10) continue;

                    var parts = trimmed.Split('\t', ' ', ',');
                    if (parts.Length >= 1 && parts[0].Length == 64)
                        knownHashes.Add(parts[0].ToLowerInvariant());

                    if (parts.Length >= 2 && parts[1].Length == 64)
                        knownHashes.Add(parts[1].ToLowerInvariant());
                }

                progress?.Report($"Fuente {url}: {knownHashes.Count} hashes acumulados");
            }
            catch (HttpRequestException ex)
            {
                var msg = $"Error de red al descargar {url}: {ex.Message}";
                progress?.Report(msg);
                UpdateError?.Invoke(msg);
            }
            catch (TaskCanceledException)
            {
                var msg = $"Tiempo de espera agotado para {url}";
                progress?.Report(msg);
                UpdateError?.Invoke(msg);
            }
            catch (Exception ex)
            {
                var msg = $"Error descargando {url}: {ex.Message}";
                progress?.Report(msg);
                UpdateError?.Invoke(msg);
            }
        }

        var dbPath = Path.Combine(_defDir, "malware_hashes.txt");

        var existingHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (File.Exists(dbPath))
        {
            foreach (var line in await File.ReadAllLinesAsync(dbPath))
            {
                var t = line.Trim();
                if (t.Length > 0)
                    existingHashes.Add(t);
            }
        }

        var newHashes = knownHashes.Where(h => !existingHashes.Contains(h)).ToList();

        var allHashes = existingHashes;
        allHashes.UnionWith(knownHashes);
        await File.WriteAllLinesAsync(dbPath, allHashes);

        KnownThreats = allHashes.Count;
        LastUpdate = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
        UpdateStatus = $"Actualizado: {KnownThreats} amenazas ({newHashes.Count} nuevas)";
        SaveMetadata();

        progress?.Report($"Actualización completada. {KnownThreats} amenazas conocidas ({newHashes.Count} nuevas).");

        DefinitionsUpdated?.Invoke(LastUpdate, KnownThreats);
        _updating = false;
        return knownHashes.Count;
    }

    public void ForceUpdate()
    {
        Task.Run(async () =>
        {
            try
            {
                await UpdateDefinitionsAsync();
            }
            catch { }
        });
    }

    public bool IsKnownThreat(string filePath)
    {
        try
        {
            using var stream = File.OpenRead(filePath);
            using var sha256 = SHA256.Create();
            var hash = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();

            var dbPath = Path.Combine(_defDir, "malware_hashes.txt");
            if (!File.Exists(dbPath)) return false;

            var lines = File.ReadLines(dbPath);
            return lines.Any(l => l.Trim().Equals(hash, StringComparison.OrdinalIgnoreCase));
        }
        catch { return false; }
    }

    private void SaveMetadata()
    {
        var meta = new { LastUpdate, KnownThreats };
        File.WriteAllText(Path.Combine(_defDir, "metadata.json"), JsonSerializer.Serialize(meta));
    }

    private void LoadMetadata()
    {
        try
        {
            var path = Path.Combine(_defDir, "metadata.json");
            if (!File.Exists(path)) return;
            var json = File.ReadAllText(path);
            var meta = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
            if (meta != null)
            {
                if (meta.TryGetValue("LastUpdate", out var lu)) LastUpdate = lu.GetString() ?? "Nunca";
                if (meta.TryGetValue("KnownThreats", out var kt)) KnownThreats = kt.GetInt32();
            }
        }
        catch { }
    }

    public void Dispose()
    {
        _updateTimer?.Dispose();
        _client?.Dispose();
    }
}
