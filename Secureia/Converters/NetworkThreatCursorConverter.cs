using System.Globalization;
using System.Windows.Data;
using System.Windows.Input;

namespace Secureia.Converters;

public class NetworkThreatCursorConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is true ? Cursors.Hand : Cursors.Arrow;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}