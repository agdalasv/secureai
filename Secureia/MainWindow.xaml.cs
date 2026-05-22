using System.Windows;
using System.Windows.Media;
using System.Windows.Forms;
using Secureia.ViewModels;

namespace Secureia;

public partial class MainWindow : Window
{
    private NotifyIcon? _trayIcon;

    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;

        try
        {
            var icoPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "app.ico");
            var icon = System.IO.File.Exists(icoPath)
                ? new System.Drawing.Icon(icoPath)
                : System.Drawing.SystemIcons.Application;

            _trayIcon = new NotifyIcon
            {
                Icon = icon,
                Text = "Secure AI - Asistente de Seguridad",
                Visible = true
            };

            _trayIcon.Click += (_, _) => RestoreWindow();

            _trayIcon.ContextMenuStrip = new ContextMenuStrip();
            _trayIcon.ContextMenuStrip.Items.Add("Abrir Secure AI", null, (_, _) => RestoreWindow());
            _trayIcon.ContextMenuStrip.Items.Add("Salir", null, (_, _) =>
            {
                _trayIcon.Visible = false;
                _trayIcon.Dispose();
                System.Windows.Application.Current.Shutdown();
            });
        }
        catch { }
    }

    private void RestoreWindow()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    protected override void OnStateChanged(EventArgs e)
    {
        base.OnStateChanged(e);
        if (WindowState == WindowState.Minimized)
        {
            Hide();
            _trayIcon?.ShowBalloonTip(2000, "Secure AI",
                "Secure AI sigue ejecutándose en segundo plano.",
                ToolTipIcon.Info);
        }
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        e.Cancel = true;
        WindowState = WindowState.Minimized;
        Hide();
        _trayIcon?.ShowBalloonTip(2000, "Secure AI",
            "Secure AI se minimizó a la bandeja. Usa 'Salir' en el menú del icono para cerrar.",
            ToolTipIcon.Info);
        base.OnClosing(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        _trayIcon?.Dispose();
        base.OnClosed(e);
    }
}
