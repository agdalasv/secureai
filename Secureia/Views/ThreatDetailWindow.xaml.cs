using System.Diagnostics;
using System.Windows;
using Secureia.Models;
using Secureia.Services;

namespace Secureia.Views;

public partial class ThreatDetailWindow : Window
{
    private readonly LogEntry _entry;
    private readonly LogService _logService;
    private readonly DefenseShieldAI? _shield;
    private readonly WindowsDefenderService? _defenderService;

    public bool IsResolved { get; private set; }

    public ThreatDetailWindow(LogEntry entry, LogService logService,
                              DefenseShieldAI? shield = null,
                              WindowsDefenderService? defenderService = null)
    {
        InitializeComponent();
        _entry = entry;
        _logService = logService;
        _shield = shield;
        _defenderService = defenderService;

        ThreatTypeText.Text = GetThreatTypeDisplay(entry.ThreatType ?? "Desconocido");
        ThreatLevelText.Text = entry.Level.ToString();
        ThreatLevelText.Foreground = entry.Level switch
        {
            ThreatLevel.Critical => System.Windows.Media.Brushes.Red,
            ThreatLevel.High => System.Windows.Media.Brushes.Orange,
            ThreatLevel.Medium => System.Windows.Media.Brushes.Yellow,
            _ => System.Windows.Media.Brushes.Gray
        };
        DescriptionText.Text = entry.Description ?? "Sin descripción disponible.";
        SourceIpText.Text = string.IsNullOrEmpty(entry.SourceIp) ? "N/A" : entry.SourceIp;
        DestIpText.Text = string.IsNullOrEmpty(entry.DestinationIp) ? "N/A" : entry.DestinationIp;
        SourcePortText.Text = entry.SourcePort > 0 ? entry.SourcePort.ToString() : "N/A";
        DestPortText.Text = entry.DestinationPort > 0 ? entry.DestinationPort.ToString() : "N/A";
        StatusText.Text = entry.IsResolved ? "Resuelta" : "Pendiente";

        MarkFalsePositiveBtn.Click += (_, _) => MarkAsFalsePositive();
        EliminateBtn.Click += (_, _) => EliminateThreat();
        CancelBtn.Click += (_, _) => Close();

        if (entry.IsResolved)
        {
            MarkFalsePositiveBtn.IsEnabled = false;
            EliminateBtn.IsEnabled = false;
            ResultText.Text = "Esta amenaza ya ha sido procesada.";
        }
    }

    private static string GetThreatTypeDisplay(string type) => type switch
    {
        "DoS/DDoS" => "Ataque DoS/DDoS",
        "Backdoor" => "Puerta Trasera (Backdoor)",
        "ReverseShell" => "Shell Inversa",
        "C2/Botnet" => "Servidor C2 / Botnet",
        "Botnet" => "Conexión Botnet",
        "PortScan" => "Escaneo de Puertos",
        "WiFiDeauth" => "Desautenticación Wi-Fi",
        "DnsTunneling" => "Túnel DNS",
        "RDP" => "Escritorio Remoto (RDP)",
        "Malware" => "Dominio Malicioso",
        "ConexionRemota" => "Conexión Remota No Autorizada",
        "PuertoAbierto" => "Puerto Sospechoso Abierto",
        "PuertosAnormales" => "Múltiples Puertos Anormales",
        _ => type
    };

    private void MarkAsFalsePositive()
    {
        _entry.IsResolved = true;

        if (!string.IsNullOrEmpty(_entry.DestinationIp))
            _shield?.UnblockIp(_entry.DestinationIp);

        _logService.Log(new LogEntry
        {
            Event = $"Falso positivo marcado: {_entry.Event}",
            FilePath = _entry.DestinationIp ?? _entry.SourceIp ?? "",
            Description = $"El usuario marcó esta amenaza como falso positivo: {_entry.ThreatType}",
            ThreatType = _entry.ThreatType,
            ActionTaken = "Falso positivo",
            User = Environment.UserName
        });

        IsResolved = true;
        ResultText.Text = "✓ Marcado como falso positivo. La IP ha sido desbloqueada si estaba bloqueada.";
        ResultText.Foreground = System.Windows.Media.Brushes.LightGreen;
        MarkFalsePositiveBtn.IsEnabled = false;
        EliminateBtn.IsEnabled = false;
    }

    private void EliminateThreat()
    {
        _entry.IsResolved = true;

        var blockedIp = _entry.DestinationIp ?? _entry.SourceIp;
        if (!string.IsNullOrEmpty(blockedIp))
        {
            if (_shield != null)
            {
                _shield.BlockIp(blockedIp);
            }
            else
            {
                BlockIpViaFirewall(blockedIp);
            }
        }

        _logService.Log(new LogEntry
        {
            Event = $"Amenaza eliminada: {_entry.Event}",
            FilePath = blockedIp ?? "",
            Description = $"Amenaza eliminada por el usuario: {_entry.ThreatType}. IP {blockedIp} bloqueada en firewall.",
            ThreatType = _entry.ThreatType,
            ActionTaken = "Amenaza eliminada",
            User = Environment.UserName
        });

        IsResolved = true;
        ResultText.Text = $"✓ Amenaza eliminada. La IP {blockedIp} ha sido bloqueada en el firewall de Windows.";
        ResultText.Foreground = System.Windows.Media.Brushes.LightGreen;
        MarkFalsePositiveBtn.IsEnabled = false;
        EliminateBtn.IsEnabled = false;
    }

    private static void BlockIpViaFirewall(string ip)
    {
        Task.Run(() =>
        {
            try
            {
                var ruleName = $"SecureAI_Block_{ip.Replace('.', '_')}";
                var psi1 = new ProcessStartInfo("netsh",
                    $"advfirewall firewall add rule name=\"{ruleName}_in\" dir=in action=block remoteip={ip} protocol=any")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc1 = Process.Start(psi1);
                proc1?.WaitForExit(10000);

                var psi2 = new ProcessStartInfo("netsh",
                    $"advfirewall firewall add rule name=\"{ruleName}_out\" dir=out action=block remoteip={ip} protocol=any")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc2 = Process.Start(psi2);
                proc2?.WaitForExit(10000);
            }
            catch { }
        });
    }
}