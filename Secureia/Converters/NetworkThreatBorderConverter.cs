using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace Secureia.Converters;

public class NetworkThreatBorderConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is true
            ? new SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 82, 82))
            : new SolidColorBrush(System.Windows.Media.Color.FromRgb(15, 52, 96));
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}