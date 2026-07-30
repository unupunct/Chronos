using System.IO;

namespace Chronos.Services;

/// <summary>
/// Minimal rolling file logger. Writes next to the exe when possible,
/// otherwise falls back to %LOCALAPPDATA%\Chronos.
/// </summary>
public static class LogService
{
    private static readonly object Gate = new();
    private static string? _path;

    public static string LogPath => _path ??= ResolvePath();

    private static string ResolvePath()
    {
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "Chronos.log"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Chronos", "Chronos.log"),
        };
        foreach (var c in candidates)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(c)!);
                File.AppendAllText(c, "");
                return c;
            }
            catch { /* try next */ }
        }
        return Path.Combine(Path.GetTempPath(), "Chronos.log");
    }

    public static void Info(string message) => Write("INFO", message);
    public static void Warn(string message) => Write("WARN", message);
    public static void Error(string message, Exception? ex = null) =>
        Write("ERROR", ex is null ? message : $"{message}: {ex.GetType().Name}: {ex.Message}");

    private static void Write(string level, string message)
    {
        try
        {
            lock (Gate)
            {
                var f = new FileInfo(LogPath);
                if (f.Exists && f.Length > 2_000_000) f.Delete(); // simple 2 MB roll
                File.AppendAllText(LogPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{level}] {message}{Environment.NewLine}");
            }
        }
        catch { /* logging must never crash the app */ }
    }
}
