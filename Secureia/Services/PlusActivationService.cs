using Secureia.Models;

namespace Secureia.Services;

public class PlusActivationService
{
    private readonly ConfigService _configService;

    public bool IsPlusActive => _configService.Config.PlusActivated;

    public string? PlusSerialKey => _configService.Config.PlusSerialKey;

    public PlusActivationService(ConfigService configService)
    {
        _configService = configService;
    }

    public bool Activate(string serialKey)
    {
        if (string.IsNullOrWhiteSpace(serialKey)) return false;
        if (!SerialKeyGenerator.ValidateKey(serialKey)) return false;

        _configService.Config.PlusActivated = true;
        _configService.Config.PlusSerialKey = serialKey.Trim();
        _configService.Config.PlusActivationDate = DateTime.Now;
        _configService.Save();
        return true;
    }

    public void Deactivate()
    {
        _configService.Config.PlusActivated = false;
        _configService.Config.PlusSerialKey = null;
        _configService.Config.PlusActivationDate = null;
        _configService.Save();
    }

    public string GetFormattedKey()
    {
        var key = _configService.Config.PlusSerialKey;
        if (string.IsNullOrEmpty(key)) return "";
        return key;
    }
}
