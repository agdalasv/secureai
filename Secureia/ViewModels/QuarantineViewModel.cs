using System.Collections.ObjectModel;
using System.Windows.Input;
using Secureia.Models;
using Secureia.Services;

namespace Secureia.ViewModels;

public class QuarantineViewModel : ViewModelBase
{
    private readonly QuarantineService _quarantineService;
    private readonly LogService _logService;

    public ObservableCollection<QuarantineItem> Items { get; } = new();

    public ICommand RestoreCommand { get; }
    public ICommand DeleteCommand { get; }
    public ICommand DeleteAllCommand { get; }
    public ICommand RefreshCommand { get; }

    public QuarantineViewModel(QuarantineService quarantineService, LogService logService)
    {
        _quarantineService = quarantineService;
        _logService = logService;

        RestoreCommand = new RelayCommand(param => Restore(param as QuarantineItem));
        DeleteCommand = new RelayCommand(param => Delete(param as QuarantineItem));
        DeleteAllCommand = new RelayCommand(_ => DeleteAll());
        RefreshCommand = new RelayCommand(_ => LoadItems());
    }

    public void LoadItems()
    {
        Items.Clear();
        foreach (var item in _quarantineService.Items)
            Items.Add(item);
    }

    private void Restore(QuarantineItem? item)
    {
        if (item == null) return;
        _quarantineService.Restore(item);
        _logService.Log(new LogEntry
        {
            Event = "Archivo restaurado de cuarentena",
            FilePath = item.OriginalPath,
            ActionTaken = "Restaurar",
            User = Environment.UserName
        });
        Items.Remove(item);
    }

    private void Delete(QuarantineItem? item)
    {
        if (item == null) return;
        _quarantineService.Delete(item);
        _logService.Log(new LogEntry
        {
            Event = "Archivo eliminado de cuarentena",
            FilePath = item.OriginalPath,
            ActionTaken = "Eliminar",
            User = Environment.UserName
        });
        Items.Remove(item);
    }

    private void DeleteAll()
    {
        _quarantineService.DeleteAll();
        Items.Clear();
    }
}
