using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Secureia.Models;

namespace Secureia.Views;

public partial class HistoryView : UserControl
{
    public HistoryView()
    {
        InitializeComponent();
    }

    private void ListBoxItem_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        var entry = (sender as FrameworkElement)?.DataContext as LogEntry;
        if (entry == null || !entry.IsNetworkThreat) return;

        var vm = DataContext as ViewModels.MainViewModel;
        if (vm == null || !vm.IsPlusActive) return;

        vm.History.OpenThreatDetailCommand.Execute(entry);
    }
}
