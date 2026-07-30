using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Chronos.ViewModels;

namespace Chronos;

public partial class MainWindow : Window
{
    /// <summary>Shared instance used by chart bar width MultiBindings in XAML.</summary>
    public static readonly FractionWidthConverter FractionWidth = new();

    private readonly MainViewModel _vm = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _vm;
        Loaded += async (_, _) =>
        {
            ApplyWin11Chrome();
            await _vm.RefreshAsync(force: true);
        };
    }

    // ------------------------------------------------------------------ window chrome

    private void OnMinimize(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void OnMaximize(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void OnClose(object sender, RoutedEventArgs e) => Close();

    private void CloseExportPopup(object sender, RoutedEventArgs e) => ExportToggle.IsChecked = false;

    /// <summary>Dark title-bar hints + rounded corners on Windows 11. Safe no-op on older builds.</summary>
    private void ApplyWin11Chrome()
    {
        try
        {
            var hwnd = new WindowInteropHelper(this).Handle;
            var on = 1;
            _ = DwmSetWindowAttribute(hwnd, 20 /*DWMWA_USE_IMMERSIVE_DARK_MODE*/, ref on, sizeof(int));
            var round = 2; // DWMWCP_ROUND
            _ = DwmSetWindowAttribute(hwnd, 33 /*DWMWA_WINDOW_CORNER_PREFERENCE*/, ref round, sizeof(int));
        }
        catch { /* purely cosmetic */ }
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(nint hwnd, int attr, ref int value, int size);
}
