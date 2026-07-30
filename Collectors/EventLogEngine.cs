using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using Chronos.Models;
using Chronos.Services;

namespace Chronos.Collectors;

/// <summary>
/// Executes the EventRules table against the Windows Event Log.
/// Channels are read in parallel; within a channel, rules are grouped into
/// XPath chunks small enough to stay under the event query complexity limit.
/// </summary>
public sealed class EventLogEngine
{
    private const int MaxIdsPerQuery = 10;

    /// <summary>Human-readable notes about anything that could not be read.</summary>
    public ConcurrentBag<string> Warnings { get; } = new();

    public List<TimelineEvent> Collect(DateTime from, DateTime to, Action<string>? progress = null)
    {
        var results = new ConcurrentBag<TimelineEvent>();
        var reported = new ConcurrentDictionary<string, bool>();

        // flatten to independent (channel, dispatch map, xpath) work items so every
        // query runs in parallel, not just every channel
        var work = new List<(string Channel, Dictionary<(string, int), EventRule> Map, string XPath)>();
        foreach (var group in EventRules.All.GroupBy(r => r.Channel))
        {
            var rules = group.ToList();
            var map = new Dictionary<(string, int), EventRule>();
            foreach (var rule in rules)
                foreach (var id in rule.Ids)
                    map[(rule.Provider.ToLowerInvariant(), id)] = rule;
            foreach (var xpath in BuildQueries(rules, from, to))
                work.Add((group.Key, map, xpath));
        }

        Parallel.ForEach(work, new ParallelOptions { MaxDegreeOfParallelism = 8 }, item =>
        {
            progress?.Invoke($"Reading {item.Channel}...");
            try
            {
                RunQuery(item.Channel, item.Map, item.XPath, results);
            }
            catch (UnauthorizedAccessException)
            {
                if (reported.TryAdd(item.Channel, true))
                    Warnings.Add(item.Channel == "Security"
                        ? "Security log requires administrator rights. Run Chronos as administrator to see logins, account and audit events."
                        : $"Access denied reading '{item.Channel}'.");
            }
            catch (EventLogNotFoundException)
            {
                if (reported.TryAdd(item.Channel, true))
                    Warnings.Add($"Event log channel '{item.Channel}' does not exist on this system.");
            }
            catch (EventLogException ex)
            {
                if (reported.TryAdd(item.Channel, true))
                    Warnings.Add($"Could not read '{item.Channel}': {ex.Message}");
            }
            catch (Exception ex)
            {
                LogService.Error($"Channel {item.Channel} failed", ex);
                if (reported.TryAdd(item.Channel, true))
                    Warnings.Add($"Could not read '{item.Channel}': {ex.Message}");
            }
        });

        return results.ToList();
    }

    private static void RunQuery(
        string channel, Dictionary<(string, int), EventRule> map, string xpath, ConcurrentBag<TimelineEvent> sink)
    {
        var query = new EventLogQuery(channel, PathType.LogName, xpath) { ReverseDirection = true };
        using var reader = new EventLogReader(query);

        for (EventRecord? record = reader.ReadEvent(); record is not null; record = reader.ReadEvent())
        {
            using (record)
            {
                var provider = record.ProviderName?.ToLowerInvariant() ?? "";
                if (!map.TryGetValue((provider, record.Id), out var rule)) continue;

                string[] props;
                try
                {
                    props = record.Properties.Select(p => PropToString(p.Value)).ToArray();
                }
                catch { props = Array.Empty<string>(); }

                try
                {
                    var ev = rule.Map(record, props);
                    if (ev is not null) sink.Add(ev);
                }
                catch (Exception ex)
                {
                    LogService.Error($"Rule map failed for {provider}/{record.Id}", ex);
                }
            }
        }
    }

    private static string PropToString(object? value) => value switch
    {
        null => "",
        byte[] bytes => Convert.ToHexString(bytes),
        System.Security.Principal.SecurityIdentifier sid => sid.Value,
        DateTime dt => dt.ToString("yyyy-MM-dd HH:mm:ss"),
        _ => value.ToString() ?? "",
    };

    /// <summary>Builds chunked XPath queries: time window + (provider, ids) conditions.</summary>
    private static IEnumerable<string> BuildQueries(List<EventRule> rules, DateTime from, DateTime to)
    {
        var time = $"TimeCreated[@SystemTime>='{Iso(from)}' and @SystemTime<='{Iso(to)}']";

        // one condition group per provider, chunk providers so total id count stays low
        var providerGroups = rules
            .GroupBy(r => r.Provider, StringComparer.OrdinalIgnoreCase)
            .Select(g => (Provider: g.Key, Ids: g.SelectMany(r => r.Ids).Distinct().ToArray()))
            .ToList();

        var chunk = new List<(string Provider, int[] Ids)>();
        var count = 0;
        foreach (var pg in providerGroups)
        {
            if (count + pg.Ids.Length > MaxIdsPerQuery && chunk.Count > 0)
            {
                yield return Compose(chunk, time);
                chunk.Clear();
                count = 0;
            }
            chunk.Add(pg);
            count += pg.Ids.Length;
        }
        if (chunk.Count > 0) yield return Compose(chunk, time);
    }

    private static string Compose(List<(string Provider, int[] Ids)> groups, string time)
    {
        var parts = groups.Select(g =>
        {
            var ids = string.Join(" or ", g.Ids.Select(i => $"EventID={i}"));
            return $"(Provider[@Name='{g.Provider}'] and ({ids}))";
        });
        return $"*[System[{time} and ({string.Join(" or ", parts)})]]";
    }

    private static string Iso(DateTime local) =>
        local.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
}
