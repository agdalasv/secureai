using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;

namespace Secureia.Views;

public partial class SettingsView : UserControl
{
    public SettingsView()
    {
        InitializeComponent();
    }

    private void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        try
        {
            var psi = new ProcessStartInfo(e.Uri.AbsoluteUri)
            {
                UseShellExecute = true
            };
            Process.Start(psi);
            e.Handled = true;
        }
        catch { }
    }

    private void Btc_MouseDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        try
        {
            Clipboard.SetText("3L8f3v6BWwL7KBcb8AMZQ2bpE3ACne2EUf");
            MessageBox.Show("Dirección BTC copiada al portapapeles.", "Secure AI",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch { }
    }
}
