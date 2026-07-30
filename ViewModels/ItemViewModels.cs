using System.Windows.Media;
using Chronos.Models;

namespace Chronos.ViewModels;

/// <summary>Wraps one TimelineEvent for display: category visuals, expand state, group key.</summary>
public sealed class EventItemViewModel : ObservableObject
{
    public TimelineEvent Model { get; }
    private readonly CategoryMeta _meta;

    public EventItemViewModel(TimelineEvent model)
    {
        Model = model;
        _meta = CategoryMeta.Get(model.Category);
    }

    public DateTime Timestamp => Model.Timestamp;
    public string Time => Model.Timestamp.ToString("HH:mm:ss");
    public string Title => Model.Title;
    public string Description => Model.Description;
    public string Source => Model.Source;
    public string CategoryName => _meta.DisplayName;
    public string Glyph => _meta.Glyph;
    public Brush CategoryBrush => _meta.Brush;
    public EventSeverity Severity => Model.Severity;
    public string? User => Model.User;
    public IReadOnlyList<KeyValuePair<string, string>> Details => Model.Details;
    public bool HasUser => !string.IsNullOrEmpty(Model.User);

    /// <summary>Timeline group header text; assigned when the filter/zoom pipeline runs.</summary>
    public string GroupKey { get; set; } = "";

    private bool _isExpanded;
    public bool IsExpanded { get => _isExpanded; set => Set(ref _isExpanded, value); }

    public Brush SeverityBrush => Severity switch
    {
        EventSeverity.Critical => Brushes.IndianRed,
        EventSeverity.Warning => Brushes.Orange,
        EventSeverity.Success => Brushes.MediumSeaGreen,
        _ => Brushes.SlateGray,
    };
}

/// <summary>Checkbox item for the category / severity filter lists.</summary>
public sealed class FilterItemViewModel : ObservableObject
{
    private bool _isChecked = true;
    public bool IsChecked
    {
        get => _isChecked;
        set { if (Set(ref _isChecked, value)) Changed?.Invoke(); }
    }

    public string Label { get; init; } = "";
    public string Glyph { get; init; } = "";
    public Brush? Brush { get; init; }
    public object? Tag { get; init; }
    public Action? Changed { get; set; }

    public void SetSilently(bool value) { _isChecked = value; OnPropertyChanged(nameof(IsChecked)); }
}
