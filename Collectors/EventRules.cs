using System.Diagnostics.Eventing.Reader;
using Chronos.Models;

namespace Chronos.Collectors;

/// <summary>
/// A declarative mapping from one Windows Event Log (channel, provider, event id)
/// to a timeline event. Map returns null to drop a record (e.g. noisy logon types).
/// </summary>
public sealed record EventRule(
    string Channel,
    string Provider,
    int[] Ids,
    Func<EventRecord, string[], TimelineEvent?> Map);

/// <summary>The full rule table that defines what Chronos knows how to read.</summary>
public static class EventRules
{
    private static TimelineEvent E(
        EventRecord r, EventCategory cat, EventSeverity sev, string title, string desc,
        params (string Key, string Value)[] details)
    {
        var ev = new TimelineEvent
        {
            Timestamp = r.TimeCreated ?? DateTime.MinValue,
            Category = cat,
            Severity = sev,
            Title = title,
            Description = desc,
            Source = $"{r.LogName} / {r.ProviderName}",
            EventId = r.Id,
            User = TryUser(r),
        };
        ev.Details.Add(new("Event ID", r.Id.ToString()));
        ev.Details.Add(new("Log", r.LogName ?? ""));
        ev.Details.Add(new("Provider", r.ProviderName ?? ""));
        foreach (var (k, v) in details)
            if (!string.IsNullOrWhiteSpace(v))
                ev.Details.Add(new(k, v));
        return ev;
    }

    private static string? TryUser(EventRecord r)
    {
        try
        {
            if (r.UserId is null) return null;
            return ((System.Security.Principal.SecurityIdentifier)r.UserId)
                .Translate(typeof(System.Security.Principal.NTAccount)).ToString();
        }
        catch { return r.UserId?.ToString(); }
    }

    private static string P(string[] p, int i) => i >= 0 && i < p.Length ? p[i] : "";

    /// <summary>First line of the rendered event message; used only for rare events.</summary>
    private static string Msg(EventRecord r)
    {
        try
        {
            var m = r.FormatDescription();
            if (string.IsNullOrWhiteSpace(m)) return "";
            var line = m.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries);
            return line.Length > 0 ? line[0].Trim() : "";
        }
        catch { return ""; }
    }

    // ------------------------------------------------------------------ rules

    public static readonly IReadOnlyList<EventRule> All = Build();

    private static List<EventRule> Build()
    {
        var rules = new List<EventRule>();
        void Add(string channel, string provider, int[] ids, Func<EventRecord, string[], TimelineEvent?> map)
            => rules.Add(new EventRule(channel, provider, ids, map));

        const string Sys = "System";
        const string App = "Application";

        // ---------------- Windows lifecycle: boot / shutdown / sleep -----------------

        Add(Sys, "EventLog", new[] { 6005 }, (r, p) =>
            E(r, EventCategory.System, EventSeverity.Success, "System boot",
              "Windows started (event log service began)."));

        Add(Sys, "EventLog", new[] { 6006 }, (r, p) =>
            E(r, EventCategory.System, EventSeverity.Information, "Clean shutdown",
              "Windows shut down normally (event log service stopped)."));

        Add(Sys, "EventLog", new[] { 6008 }, (r, p) =>
            E(r, EventCategory.System, EventSeverity.Critical, "Unexpected shutdown",
              $"The previous shutdown at {P(p, 0)} {P(p, 1)} was unexpected (power loss, crash or forced power-off)."));

        Add(Sys, "Microsoft-Windows-Kernel-Power", new[] { 41 }, (r, p) =>
            E(r, EventCategory.System, EventSeverity.Critical, "Kernel-Power 41 (dirty reboot)",
              "The system rebooted without a clean shutdown. Possible power loss, hang or crash.",
              ("BugcheckCode", P(p, 0))));

        Add(Sys, "Microsoft-Windows-Kernel-Power", new[] { 42 }, (r, p) =>
            E(r, EventCategory.System, EventSeverity.Information, "Entering sleep",
              "The system is entering a low-power sleep state."));

        Add(Sys, "Microsoft-Windows-Power-Troubleshooter", new[] { 1 }, (r, p) =>
            E(r, EventCategory.System, EventSeverity.Information, "Resumed from sleep",
              "The system returned from a low-power state.",
              ("Sleep time", P(p, 0)), ("Wake time", P(p, 1))));

        Add(Sys, "USER32", new[] { 1074 }, (r, p) =>
        {
            var kind = P(p, 4);
            var title = kind.Contains("restart", StringComparison.OrdinalIgnoreCase) ? "Restart initiated"
                      : kind.Contains("power off", StringComparison.OrdinalIgnoreCase) ? "Shutdown initiated"
                      : "Shutdown/restart initiated";
            return E(r, EventCategory.System, EventSeverity.Information, title,
                $"{P(p, 6)} initiated a {kind} via {P(p, 0)}. Reason: {P(p, 2)}",
                ("Process", P(p, 0)), ("Reason", P(p, 2)), ("Type", kind), ("Comment", P(p, 5)));
        });

        Add(Sys, "Microsoft-Windows-Kernel-Boot", new[] { 27 }, (r, p) =>
        {
            var type = P(p, 0) switch
            {
                "0" or "0x0" => "Cold boot (full startup)",
                "1" or "0x1" => "Fast Startup (hybrid boot)",
                "2" or "0x2" => "Resume from hibernation",
                _ => "Boot (type " + P(p, 0) + ")",
            };
            return E(r, EventCategory.System, EventSeverity.Information, type,
                "Windows boot type recorded by the kernel.");
        });

        Add(Sys, "Microsoft-Windows-Eventlog", new[] { 104 }, (r, p) =>
            E(r, EventCategory.Security, EventSeverity.Warning, "Event log cleared",
              $"The '{P(p, 2)}' event log was cleared by {P(p, 1)}\\{P(p, 0)}.",
              ("Cleared log", P(p, 2))));

        // ---------------- Windows Update -----------------

        Add(Sys, "Microsoft-Windows-WindowsUpdateClient", new[] { 19 }, (r, p) =>
            E(r, EventCategory.Updates, EventSeverity.Success, "Update installed",
              $"Installed successfully: {P(p, 0)}", ("Update", P(p, 0))));

        Add(Sys, "Microsoft-Windows-WindowsUpdateClient", new[] { 20 }, (r, p) =>
            E(r, EventCategory.Updates, EventSeverity.Warning, "Update failed",
              $"Installation failure: {P(p, 1)} (error {P(p, 0)})",
              ("Update", P(p, 1)), ("Error code", P(p, 0))));

        Add("Setup", "Microsoft-Windows-Servicing", new[] { 1, 2, 3, 4 }, (r, p) =>
        {
            var pkg = P(p, 0);
            return r.Id switch
            {
                1 => E(r, EventCategory.Updates, EventSeverity.Information, "Update package staged",
                       $"Servicing started for {pkg}.", ("Package", pkg)),
                2 => E(r, EventCategory.Updates, EventSeverity.Success, "Update package installed",
                       $"Servicing completed for {pkg} (state: {P(p, 2)}).", ("Package", pkg), ("State", P(p, 2))),
                3 => E(r, EventCategory.Updates, EventSeverity.Information, "Update requires restart",
                       $"{pkg} needs a reboot to finish installing.", ("Package", pkg)),
                _ => E(r, EventCategory.Updates, EventSeverity.Success, "Update finalized",
                       $"Servicing finalized {pkg} after reboot.", ("Package", pkg)),
            };
        });

        // ---------------- Services and scheduled tasks -----------------

        Add(Sys, "Service Control Manager", new[] { 7045 }, (r, p) =>
            E(r, EventCategory.Services, EventSeverity.Information, "Service installed",
              $"New service '{P(p, 0)}' ({P(p, 1)}), start type: {P(p, 3)}, account: {P(p, 4)}.",
              ("Service", P(p, 0)), ("Image path", P(p, 1)), ("Start type", P(p, 3)), ("Account", P(p, 4))));

        Add(Sys, "Service Control Manager", new[] { 7034 }, (r, p) =>
            E(r, EventCategory.Services, EventSeverity.Warning, "Service crashed",
              $"Service '{P(p, 0)}' terminated unexpectedly ({P(p, 1)} time(s)).",
              ("Service", P(p, 0))));

        Add(Sys, "Service Control Manager", new[] { 7000 }, (r, p) =>
            E(r, EventCategory.Services, EventSeverity.Warning, "Service failed to start",
              $"Service '{P(p, 0)}' failed to start: {P(p, 1)}",
              ("Service", P(p, 0)), ("Error", P(p, 1))));

        Add(Sys, "Service Control Manager", new[] { 7040 }, (r, p) =>
        {
            // BITS flips between auto/demand start constantly by design - pure noise
            var name = P(p, 0);
            if (name.Contains("Background Intelligent Transfer", StringComparison.OrdinalIgnoreCase)) return null;
            return E(r, EventCategory.Services, EventSeverity.Information, "Service start type changed",
                $"'{name}' changed from {P(p, 1)} to {P(p, 2)}.",
                ("Service", name), ("From", P(p, 1)), ("To", P(p, 2)));
        });

        Add("Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-TaskScheduler", new[] { 106 }, (r, p) =>
            E(r, EventCategory.Services, EventSeverity.Information, "Scheduled task created",
              $"Task '{P(p, 0)}' was registered by {P(p, 1)}.",
              ("Task", P(p, 0)), ("Registered by", P(p, 1))));

        Add("Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-TaskScheduler", new[] { 141 }, (r, p) =>
            E(r, EventCategory.Services, EventSeverity.Information, "Scheduled task deleted",
              $"Task '{P(p, 0)}' was deleted by {P(p, 1)}.",
              ("Task", P(p, 0)), ("Deleted by", P(p, 1))));

        // ---------------- Hardware: devices, disks, memory, thermal -----------------

        Add(Sys, "Microsoft-Windows-Kernel-PnP", new[] { 400 }, (r, p) =>
        {
            var id = P(p, 0);
            var (kind, sev) = ClassifyDevice(id);
            return E(r, EventCategory.Hardware, sev, $"{kind} configured",
                $"Device installed or configured: {Friendly(id)}", ("Device instance", id));
        });

        Add(Sys, "Microsoft-Windows-Kernel-PnP", new[] { 420 }, (r, p) =>
        {
            var id = P(p, 0);
            var (kind, _) = ClassifyDevice(id);
            return E(r, EventCategory.Hardware, EventSeverity.Information, $"{kind} removed",
                $"Device removed: {Friendly(id)}", ("Device instance", id));
        });

        Add(Sys, "Microsoft-Windows-UserPnp", new[] { 20001 }, (r, p) =>
            E(r, EventCategory.Hardware, EventSeverity.Success, "Driver installed",
              $"Driver installed for {Friendly(P(p, 3))} ({P(p, 0)} v{P(p, 1)}).",
              ("Driver", P(p, 0)), ("Version", P(p, 1)), ("Device", P(p, 3)), ("Status", P(p, 5))));

        Add(Sys, "Microsoft-Windows-UserPnp", new[] { 20003 }, (r, p) =>
            E(r, EventCategory.Hardware, EventSeverity.Information, "Device driver service added",
              $"Driver service '{P(p, 0)}' added for device {Friendly(P(p, 2))}.",
              ("Service", P(p, 0)), ("Device", P(p, 2))));

        Add(Sys, "disk", new[] { 7 }, (r, p) =>
            E(r, EventCategory.Errors, EventSeverity.Warning, "Disk bad block",
              $"The device {P(p, 0)} has a bad block.", ("Device", P(p, 0))));

        Add(Sys, "disk", new[] { 51 }, (r, p) =>
            E(r, EventCategory.Errors, EventSeverity.Warning, "Disk paging error",
              $"An error was detected on device {P(p, 0)} during a paging operation.", ("Device", P(p, 0))));

        Add(Sys, "disk", new[] { 52 }, (r, p) =>
            E(r, EventCategory.Hardware, EventSeverity.Critical, "SMART failure predicted",
              $"The driver has detected that device {P(p, 0)} is predicting failure (S.M.A.R.T.). Back up your data immediately.",
              ("Device", P(p, 0))));

        Add(Sys, "Ntfs", new[] { 55 }, (r, p) =>
            E(r, EventCategory.Errors, EventSeverity.Critical, "File system corruption",
              $"NTFS detected corruption on volume {P(p, 0)}. Run chkdsk.", ("Volume", P(p, 0))));

        Add(Sys, "Microsoft-Windows-WHEA-Logger", new[] { 1, 17, 18, 19, 20, 46, 47 }, (r, p) =>
        {
            var sev = r.Id is 18 or 20 or 46 ? EventSeverity.Critical : EventSeverity.Warning;
            return E(r, EventCategory.Hardware, sev, "Hardware error (WHEA)",
                "The hardware error architecture reported a machine-level error (CPU, memory, PCIe or cache). " +
                "Repeated WHEA errors indicate failing hardware.", ("Error source", Msg(r)));
        });

        Add(Sys, "Microsoft-Windows-Kernel-Processor-Power", new[] { 37 }, (r, p) =>
            E(r, EventCategory.Performance, EventSeverity.Warning, "CPU throttled",
              $"Processor {P(p, 0)} performance is restricted by system firmware (thermal or power limit).",
              ("Processor", P(p, 0))));

        // ---------------- Boot / shutdown performance -----------------

        Add("Microsoft-Windows-Diagnostics-Performance/Operational", "Microsoft-Windows-Diagnostics-Performance",
            new[] { 100 }, (r, p) =>
        {
            var ms = TryMs(P(p, 5));
            var sev = ms > 120_000 ? EventSeverity.Warning : EventSeverity.Information;
            return E(r, EventCategory.Performance, sev,
                ms > 0 ? $"Boot took {ms / 1000.0:0.#} s" : "Boot time recorded",
                ms > 120_000 ? "This boot was unusually long." : "Windows measured the duration of this boot.",
                ("Boot duration (ms)", ms > 0 ? ms.ToString() : P(p, 5)));
        });

        Add("Microsoft-Windows-Diagnostics-Performance/Operational", "Microsoft-Windows-Diagnostics-Performance",
            new[] { 200 }, (r, p) =>
        {
            var ms = TryMs(P(p, 3));
            var sev = ms > 60_000 ? EventSeverity.Warning : EventSeverity.Information;
            return E(r, EventCategory.Performance, sev,
                ms > 0 ? $"Shutdown took {ms / 1000.0:0.#} s" : "Shutdown time recorded",
                ms > 60_000 ? "This shutdown was unusually slow." : "Windows measured the duration of this shutdown.",
                ("Shutdown duration (ms)", ms > 0 ? ms.ToString() : P(p, 3)));
        });

        // ---------------- Errors: crashes, hangs, BSOD, WER -----------------

        Add(App, "Application Error", new[] { 1000 }, (r, p) =>
            E(r, EventCategory.Errors, EventSeverity.Warning, $"Application crash: {P(p, 0)}",
              $"{P(p, 0)} v{P(p, 1)} crashed in module {P(p, 3)} (exception {P(p, 6)}).",
              ("Application", P(p, 0)), ("Version", P(p, 1)), ("Faulting module", P(p, 3)),
              ("Exception code", P(p, 6)), ("Path", P(p, 10))));

        Add(App, "Application Hang", new[] { 1002 }, (r, p) =>
            E(r, EventCategory.Errors, EventSeverity.Warning, $"Application hang: {P(p, 0)}",
              $"{P(p, 0)} v{P(p, 1)} stopped responding and was closed.",
              ("Application", P(p, 0)), ("Version", P(p, 1))));

        Add(App, "Windows Error Reporting", new[] { 1001 }, (r, p) =>
            E(r, EventCategory.Errors, EventSeverity.Information, "Error report generated",
              $"Windows Error Reporting logged a report for {P(p, 5)} (type: {P(p, 3)}).",
              ("Program", P(p, 5)), ("Report type", P(p, 3))));

        Add(App, ".NET Runtime", new[] { 1026 }, (r, p) =>
            E(r, EventCategory.Errors, EventSeverity.Warning, ".NET application crash",
              FirstLine(P(p, 0)), ("Details", Truncate(P(p, 0), 600))));

        Add(Sys, "Microsoft-Windows-WER-SystemErrorReporting", new[] { 1001 }, (r, p) =>
            E(r, EventCategory.Errors, EventSeverity.Critical, "Blue Screen (BSOD)",
              $"The computer rebooted from a bugcheck: {P(p, 0)}",
              ("Bugcheck", P(p, 0)), ("Dump file", P(p, 1))));

        Add(App, "Microsoft-Windows-Wininit", new[] { 1001 }, (r, p) =>
            E(r, EventCategory.System, EventSeverity.Information, "CHKDSK ran at boot",
              FirstLine(P(p, 0)), ("Output", Truncate(P(p, 0), 800))));

        // ---------------- System Restore / activation -----------------

        Add(App, "Microsoft-Windows-SystemRestore", new[] { 8194 }, (r, p) =>
            E(r, EventCategory.System, EventSeverity.Success, "Restore point created",
              $"System Restore point created: {P(p, 1)}", ("Restore point", P(p, 1)), ("Type", P(p, 0))));

        Add(App, "Microsoft-Windows-Security-SPP", new[] { 12288, 12289 }, (r, p) =>
            r.Id == 12288
                ? E(r, EventCategory.System, EventSeverity.Information, "Windows activation attempt",
                    "The software protection service contacted the activation server.")
                : E(r, EventCategory.System, EventSeverity.Information, "Windows activation result",
                    FirstLine(Msg(r))));

        // ---------------- Security log (needs administrator) -----------------

        Add("Security", "Microsoft-Windows-Security-Auditing", new[] { 4624 }, (r, p) =>
        {
            // p[5]=account, p[6]=domain, p[8]=logon type
            var type = P(p, 8);
            if (type is not ("2" or "7" or "10" or "11")) return null; // keep interactive/unlock/rdp only
            var account = P(p, 5);
            if (account.EndsWith("$") || account is "SYSTEM" or "LOCAL SERVICE" or "NETWORK SERVICE" or "ANONYMOUS LOGON" or "DWM-1" or "UMFD-0") return null;
            var kind = type switch { "2" => "Interactive login", "7" => "Workstation unlocked", "10" => "Remote Desktop login", _ => "Cached login" };
            return E(r, EventCategory.Security, EventSeverity.Success, kind,
                $"{P(p, 6)}\\{account} logged on (type {type}).",
                ("Account", $"{P(p, 6)}\\{account}"), ("Logon type", type), ("Source IP", P(p, 18)));
        });

        Add("Security", "Microsoft-Windows-Security-Auditing", new[] { 4625 }, (r, p) =>
            E(r, EventCategory.Security, EventSeverity.Warning, "Failed login",
              $"Failed logon for {P(p, 6)}\\{P(p, 5)} (status {P(p, 7)}).",
              ("Account", $"{P(p, 6)}\\{P(p, 5)}"), ("Status", P(p, 7)), ("Logon type", P(p, 10)), ("Source IP", P(p, 19))));

        Add("Security", "Microsoft-Windows-Security-Auditing", new[] { 4647 }, (r, p) =>
            E(r, EventCategory.Security, EventSeverity.Information, "Logout",
              $"{P(p, 2)}\\{P(p, 1)} initiated logoff.", ("Account", $"{P(p, 2)}\\{P(p, 1)}")));

        Add("Security", "Microsoft-Windows-Security-Auditing", new[] { 4720 }, (r, p) =>
            E(r, EventCategory.Security, EventSeverity.Warning, "User account created",
              $"Account '{P(p, 0)}' was created by {P(p, 4)}.", ("New account", P(p, 0)), ("Created by", P(p, 4))));

        Add("Security", "Microsoft-Windows-Security-Auditing", new[] { 4726 }, (r, p) =>
            E(r, EventCategory.Security, EventSeverity.Warning, "User account deleted",
              $"Account '{P(p, 0)}' was deleted by {P(p, 4)}.", ("Deleted account", P(p, 0)), ("Deleted by", P(p, 4))));

        Add("Security", "Microsoft-Windows-Security-Auditing", new[] { 4722, 4725 }, (r, p) =>
            E(r, EventCategory.Security, EventSeverity.Information,
              r.Id == 4722 ? "User account enabled" : "User account disabled",
              $"Account '{P(p, 0)}' was {(r.Id == 4722 ? "enabled" : "disabled")} by {P(p, 4)}.",
              ("Account", P(p, 0))));

        Add("Security", "Microsoft-Windows-Security-Auditing", new[] { 4723, 4724 }, (r, p) =>
            E(r, EventCategory.Security, EventSeverity.Information, "Password changed",
              $"Password {(r.Id == 4723 ? "change" : "reset")} for account '{P(p, 0)}'.",
              ("Account", P(p, 0))));

        Add("Security", "Microsoft-Windows-Security-Auditing", new[] { 4728, 4732 }, (r, p) =>
        {
            var group = P(p, 2);
            var admin = group.Contains("Admin", StringComparison.OrdinalIgnoreCase);
            return E(r, EventCategory.Security, admin ? EventSeverity.Warning : EventSeverity.Information,
                admin ? "Administrator added" : "User added to group",
                $"Member {P(p, 0)} was added to group '{group}' by {P(p, 6)}.",
                ("Member", P(p, 0)), ("Group", group), ("By", P(p, 6)));
        });

        Add("Security", "Microsoft-Windows-Security-Auditing", new[] { 4733, 4729 }, (r, p) =>
        {
            var group = P(p, 2);
            var admin = group.Contains("Admin", StringComparison.OrdinalIgnoreCase);
            return E(r, EventCategory.Security, admin ? EventSeverity.Warning : EventSeverity.Information,
                admin ? "Administrator removed" : "User removed from group",
                $"Member {P(p, 0)} was removed from group '{group}'.",
                ("Member", P(p, 0)), ("Group", group));
        });

        Add("Security", "Microsoft-Windows-Security-Auditing", new[] { 4740 }, (r, p) =>
            E(r, EventCategory.Security, EventSeverity.Warning, "Account locked out",
              $"Account '{P(p, 0)}' was locked out after repeated failed logons.", ("Account", P(p, 0))));

        Add("Security", "Microsoft-Windows-Eventlog", new[] { 1102 }, (r, p) =>
            E(r, EventCategory.Security, EventSeverity.Critical, "Security audit log cleared",
              "The security event log was cleared. On a machine you do not manage, this can indicate tampering."));

        // ---------------- Windows Defender -----------------

        const string DefCh = "Microsoft-Windows-Windows Defender/Operational";
        const string DefPr = "Microsoft-Windows-Windows Defender";

        Add(DefCh, DefPr, new[] { 1116 }, (r, p) =>
            E(r, EventCategory.Defender, EventSeverity.Critical, "Malware detected",
              $"Defender detected {P(p, 7)} (severity: {P(p, 5)}).",
              ("Threat", P(p, 7)), ("Severity", P(p, 5)), ("Path", P(p, 21))));

        Add(DefCh, DefPr, new[] { 1117 }, (r, p) =>
            E(r, EventCategory.Defender, EventSeverity.Success, "Threat remediated",
              $"Defender took action on {P(p, 7)}: {P(p, 27)}.",
              ("Threat", P(p, 7)), ("Action", P(p, 27))));

        Add(DefCh, DefPr, new[] { 5001 }, (r, p) =>
            E(r, EventCategory.Defender, EventSeverity.Warning, "Real-time protection disabled",
              "Defender real-time protection was turned off."));

        Add(DefCh, DefPr, new[] { 5007 }, (r, p) =>
            E(r, EventCategory.Defender, EventSeverity.Information, "Defender configuration changed",
              $"{P(p, 2)}", ("Old value", P(p, 1)), ("New value", P(p, 2))));

        Add(DefCh, DefPr, new[] { 2000 }, (r, p) =>
            E(r, EventCategory.Defender, EventSeverity.Information, "Defender definitions updated",
              $"Security intelligence updated to version {P(p, 0)}.", ("Version", P(p, 0))));

        // ---------------- Firewall -----------------

        const string FwCh = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall";
        const string FwPr = "Microsoft-Windows-Windows Firewall With Advanced Security";

        Add(FwCh, FwPr, new[] { 2004 }, (r, p) =>
            E(r, EventCategory.Security, EventSeverity.Information, "Firewall rule added",
              $"Rule added: {P(p, 1)}", ("Rule", P(p, 1)), ("Application", P(p, 3))));

        Add(FwCh, FwPr, new[] { 2006 }, (r, p) =>
            E(r, EventCategory.Security, EventSeverity.Information, "Firewall rule deleted",
              $"Rule deleted: {P(p, 1)}", ("Rule", P(p, 1))));

        Add(FwCh, FwPr, new[] { 2003 }, (r, p) =>
            E(r, EventCategory.Security, EventSeverity.Warning, "Firewall setting changed",
              "A global Windows Firewall setting was modified."));

        // ---------------- BitLocker -----------------

        Add("Microsoft-Windows-BitLocker/BitLocker Management", "Microsoft-Windows-BitLocker-API",
            new[] { 768, 769, 770, 773, 775, 784, 785 }, (r, p) =>
            E(r, EventCategory.Security, EventSeverity.Information, "BitLocker event",
              FirstLine(Msg(r)), ("Message", Truncate(Msg(r), 400))));

        // ---------------- Networking -----------------

        Add("Microsoft-Windows-NetworkProfile/Operational", "Microsoft-Windows-NetworkProfile", new[] { 10000 }, (r, p) =>
            E(r, EventCategory.Network, EventSeverity.Success, "Network connected",
              $"Connected to network '{P(p, 1)}'.", ("Network", P(p, 1))));

        Add("Microsoft-Windows-NetworkProfile/Operational", "Microsoft-Windows-NetworkProfile", new[] { 10001 }, (r, p) =>
            E(r, EventCategory.Network, EventSeverity.Information, "Network disconnected",
              $"Disconnected from network '{P(p, 1)}'.", ("Network", P(p, 1))));

        Add("Microsoft-Windows-WLAN-AutoConfig/Operational", "Microsoft-Windows-WLAN-AutoConfig", new[] { 8001 }, (r, p) =>
            E(r, EventCategory.Network, EventSeverity.Success, "WiFi connected",
              $"Connected to wireless network '{P(p, 4)}'.", ("SSID", P(p, 4)), ("Adapter", P(p, 0))));

        Add("Microsoft-Windows-WLAN-AutoConfig/Operational", "Microsoft-Windows-WLAN-AutoConfig", new[] { 8003 }, (r, p) =>
            E(r, EventCategory.Network, EventSeverity.Information, "WiFi disconnected",
              $"Disconnected from wireless network '{P(p, 2)}'.", ("SSID", P(p, 2)), ("Reason", P(p, 5))));

        Add(App, "RasClient", new[] { 20225 }, (r, p) =>
            E(r, EventCategory.Network, EventSeverity.Success, "VPN connected",
              $"Dial-up/VPN connection '{P(p, 1)}' established.", ("Connection", P(p, 1))));

        Add(App, "RasClient", new[] { 20226 }, (r, p) =>
            E(r, EventCategory.Network, EventSeverity.Information, "VPN disconnected",
              $"Dial-up/VPN connection '{P(p, 1)}' ended (reason {P(p, 2)}).", ("Connection", P(p, 1))));

        Add(Sys, "Microsoft-Windows-DNS-Client", new[] { 1014 }, (r, p) =>
            E(r, EventCategory.Network, EventSeverity.Warning, "DNS resolution problem",
              $"Name resolution for '{P(p, 0)}' timed out.", ("Name", P(p, 0))));

        // ---------------- MSI installs -----------------

        Add(App, "MsiInstaller", new[] { 11707 }, (r, p) =>
            E(r, EventCategory.Software, EventSeverity.Success, TitleFromMsi(P(p, 0), "installed"),
              FirstLine(P(p, 0))));

        Add(App, "MsiInstaller", new[] { 11724 }, (r, p) =>
            E(r, EventCategory.Software, EventSeverity.Information, TitleFromMsi(P(p, 0), "removed"),
              FirstLine(P(p, 0))));

        Add(App, "MsiInstaller", new[] { 11728 }, (r, p) =>
            E(r, EventCategory.Software, EventSeverity.Information, TitleFromMsi(P(p, 0), "updated"),
              FirstLine(P(p, 0))));

        return rules;
    }

    // ------------------------------------------------------------------ helpers

    private static long TryMs(string s) => long.TryParse(s, out var v) ? v : 0;

    private static string FirstLine(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return "";
        var i = s.IndexOfAny(new[] { '\r', '\n' });
        return (i > 0 ? s[..i] : s).Trim();
    }

    private static string Truncate(string s, int max) =>
        string.IsNullOrEmpty(s) || s.Length <= max ? s : s[..max] + " ...";

    /// <summary>"Product: 7-Zip -- Installation completed successfully." → "7-Zip installed"</summary>
    private static string TitleFromMsi(string msg, string verb)
    {
        if (msg.StartsWith("Product: ", StringComparison.OrdinalIgnoreCase))
        {
            var rest = msg["Product: ".Length..];
            var cut = rest.IndexOf(" --", StringComparison.Ordinal);
            if (cut > 0) return $"{rest[..cut].Trim()} {verb}";
        }
        return $"Application {verb}";
    }

    /// <summary>Guess a human device kind from a PnP device instance id.</summary>
    private static (string Kind, EventSeverity Sev) ClassifyDevice(string instanceId)
    {
        var id = instanceId.ToUpperInvariant();
        if (id.StartsWith("USB")) return ("USB device", EventSeverity.Information);
        if (id.StartsWith("BTH")) return ("Bluetooth device", EventSeverity.Information);
        if (id.StartsWith("HID")) return ("Input device", EventSeverity.Information);
        if (id.StartsWith("DISPLAY")) return ("Monitor", EventSeverity.Information);
        if (id.StartsWith("SWD\\PRINTENUM") || id.Contains("PRINTER")) return ("Printer", EventSeverity.Information);
        if (id.StartsWith("SCSI") || id.StartsWith("IDE") || id.StartsWith("NVME") || id.StartsWith("STORAGE"))
            return ("Storage device", EventSeverity.Information);
        if (id.StartsWith("PCI")) return ("PCI device", EventSeverity.Information);
        if (id.StartsWith("ACPI")) return ("System device", EventSeverity.Information);
        return ("Device", EventSeverity.Information);
    }

    /// <summary>Shorten a device instance id for display.</summary>
    private static string Friendly(string instanceId)
    {
        if (string.IsNullOrWhiteSpace(instanceId)) return "(unknown device)";
        var parts = instanceId.Split('\\');
        return parts.Length >= 2 ? $"{parts[0]}\\{parts[1]}" : instanceId;
    }
}
