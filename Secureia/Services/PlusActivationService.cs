using Secureia.Models;

namespace Secureia.Services;

public class PlusActivationService
{
    private readonly ConfigService _configService;

    public bool IsPlusActive => _configService.Config.PlusActivated;

    public string? PlusSerialKey => _configService.Config.PlusSerialKey;

    public string? PlusHardwareId => _configService.Config.PlusHardwareId;

    public PlusActivationService(ConfigService configService)
    {
        _configService = configService;
    }

    public bool Activate(string serialKey)
    {
        if (string.IsNullOrWhiteSpace(serialKey)) return false;
        var cleanKey = serialKey.Trim().ToUpperInvariant();
        if (!SerialKeyGenerator.ValidateKey(cleanKey)) return false;

        var hwid = HardwareIdService.GenerateHardwareId();

        // Verificar si este serial ya fue usado en OTRA PC
        if (_configService.Config.UsedSerials.TryGetValue(cleanKey, out var boundHwId))
        {
            if (!string.Equals(boundHwId, hwid, StringComparison.OrdinalIgnoreCase))
                return false; // Serial ya activado en otra PC
        }

        // Vincular serial al hardware de esta PC
        _configService.Config.UsedSerials[cleanKey] = hwid;
        _configService.Config.PlusActivated = true;
        _configService.Config.PlusSerialKey = cleanKey;
        _configService.Config.PlusActivationDate = DateTime.Now;
        _configService.Config.PlusHardwareId = hwid;
        _configService.Save();
        return true;
    }

    public bool VerifyHardwareBinding()
    {
        if (!_configService.Config.PlusActivated) return false;
        if (string.IsNullOrEmpty(_configService.Config.PlusHardwareId)) return false;

        var currentHwid = HardwareIdService.GenerateHardwareId();
        if (!string.Equals(currentHwid, _configService.Config.PlusHardwareId, StringComparison.OrdinalIgnoreCase))
        {
            // Hardware changed - deactivate Plus
            _configService.Config.PlusActivated = false;
            _configService.Config.PlusSerialKey = null;
            _configService.Config.PlusActivationDate = null;
            _configService.Config.PlusHardwareId = null;
            _configService.Save();
            return false;
        }

        return true;
    }

    public void Deactivate()
    {
        _configService.Config.PlusActivated = false;
        _configService.Config.PlusSerialKey = null;
        _configService.Config.PlusActivationDate = null;
        _configService.Config.PlusHardwareId = null;
        _configService.Save();
    }

    public string GetFormattedKey()
    {
        var key = _configService.Config.PlusSerialKey;
        if (string.IsNullOrEmpty(key)) return "";
        return key;
    }
}
