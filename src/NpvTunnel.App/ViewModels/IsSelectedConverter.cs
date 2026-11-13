using System;
using System.Globalization;
using System.Windows.Data;

namespace NpvTunnel.App.ViewModels;

public sealed class IsSelectedConverter : IMultiValueConverter
{
	public static readonly IsSelectedConverter Instance = new IsSelectedConverter();

	public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
	{
		if (values.Length < 2)
		{
			return false;
		}
		return values[0] is ProfileItemViewModel profileItemViewModel && values[1] is ProfileItemViewModel profileItemViewModel2 && profileItemViewModel.Id == profileItemViewModel2.Id;
	}

	public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
	{
		throw new NotSupportedException();
	}
}
