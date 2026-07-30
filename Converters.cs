using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using Chronos.Models;

namespace Chronos;

/// <summary>Visible when the bound string equals the converter parameter (used for view switching).</summary>
public sealed class EqualsVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? parameter, CultureInfo c) =>
        string.Equals(value?.ToString(), parameter?.ToString(), StringComparison.OrdinalIgnoreCase)
            ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

/// <summary>
/// TwoWay: true when the bound string equals the parameter; checking the button
/// writes the parameter back (used for nav selection).
/// </summary>
public sealed class EqualsBoolConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? parameter, CultureInfo c) =>
        string.Equals(value?.ToString(), parameter?.ToString(), StringComparison.OrdinalIgnoreCase);

    public object ConvertBack(object? value, Type t, object? parameter, CultureInfo c) =>
        value is true ? parameter?.ToString() ?? Binding.DoNothing : Binding.DoNothing;
}

public sealed class SeverityBrushConverter : IValueConverter
{
    public static readonly SolidColorBrush Critical = Make("#FF6B6B");
    public static readonly SolidColorBrush Warning = Make("#FFA94D");
    public static readonly SolidColorBrush Success = Make("#3FD48A");
    public static readonly SolidColorBrush Info = Make("#8FA3B8");

    private static SolidColorBrush Make(string hex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        b.Freeze();
        return b;
    }

    public object Convert(object? value, Type t, object? p, CultureInfo c) => value switch
    {
        EventSeverity.Critical => Critical,
        EventSeverity.Warning => Warning,
        EventSeverity.Success => Success,
        _ => Info,
    };

    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

/// <summary>Collapsed when count is zero.</summary>
public sealed class CountVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) =>
        value is int i && i > 0 ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

/// <summary>3 → "3 events", 1 → "1 event".</summary>
public sealed class EventCountConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) =>
        value is int i ? (i == 1 ? "1 event" : $"{i} events") : "";

    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

/// <summary>Fraction (0..1) x parameter → width for chart bars.</summary>
public sealed class FractionWidthConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type t, object? p, CultureInfo c)
    {
        if (values.Length < 2 || values[0] is not double fraction || values[1] is not double total)
            return 0d;
        return Math.Max(2, fraction * Math.Max(0, total - 4));
    }

    public object[] ConvertBack(object v, Type[] t, object? p, CultureInfo c) => throw new NotSupportedException();
}
