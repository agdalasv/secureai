using System.Speech.Synthesis;

namespace Secureia.Services;

public class TtsService
{
    private SpeechSynthesizer? _synth;
    private bool _enabled = true;
    private int _volume = 80;
    private bool _available;

    public TtsService()
    {
        try
        {
            _synth = new SpeechSynthesizer();
            _available = true;
            SetMexicanVoice();
        }
        catch
        {
            _available = false;
            _synth = null;
        }
    }

    public bool IsAvailable => _available;

    private void SetMexicanVoice()
    {
        if (!_available || _synth == null) return;
        try
        {
            var voices = _synth.GetInstalledVoices()
                .Where(v => v.Enabled && v.VoiceInfo != null)
                .Select(v => v.VoiceInfo)
                .ToList();

            var mxVoice = voices.FirstOrDefault(v =>
                v.Culture?.Name?.StartsWith("es-MX", StringComparison.OrdinalIgnoreCase) == true);

            if (mxVoice != null)
                _synth.SelectVoice(mxVoice.Name);
            else
            {
                var esVoice = voices.FirstOrDefault(v =>
                    v.Culture?.Name?.StartsWith("es", StringComparison.OrdinalIgnoreCase) == true);
                if (esVoice != null)
                    _synth.SelectVoice(esVoice.Name);
            }
        }
        catch { }
    }

    public void SetEnabled(bool enabled) => _enabled = enabled;

    public void SetVolume(int volume)
    {
        _volume = Math.Clamp(volume, 0, 100);
    }

    public void SetVoice(string voiceName)
    {
        if (!_available || _synth == null) return;
        try { _synth.SelectVoice(voiceName); } catch { }
    }

    public List<string> GetAvailableVoices()
    {
        if (!_available || _synth == null) return new();
        try
        {
            return _synth.GetInstalledVoices()
                .Where(v => v.Enabled && v.VoiceInfo != null)
                .Select(v => v.VoiceInfo!.Name)
                .ToList()!;
        }
        catch { return new(); }
    }

    public void Speak(string text)
    {
        if (!_enabled || !_available || _synth == null) return;
        try
        {
            _synth.Volume = _volume;
            _synth.SpeakAsync(text);
        }
        catch { }
    }

    public void SpeakStartup()
    {
        Speak("Sistema asegurado");
    }

    public void SpeakThreatRemoved()
    {
        Speak("Virus eliminado");
    }

    public void SpeakCriticalThreat()
    {
        Speak("Activando medidas de seguridad");
    }
}
