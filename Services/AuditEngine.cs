using Microsoft.Win32;
using System.Security.Principal;
using WindowsSecurityAudit.Models;

namespace WindowsSecurityAudit.Services;

public sealed class AuditEngine
{
    private readonly PowerShellRunner _ps = new();

    public async Task<List<AuditResult>> RunAsync(IProgress<string>? progress = null)
    {
        var results = new List<AuditResult>();
        var checks = new (string Name, Func<Task<AuditResult>> Run)[]
        {
            ("Windows Defender", CheckDefenderAsync),
            ("Windows Firewall", CheckFirewallAsync),
            ("BitLocker", CheckBitLockerAsync),
            ("UAC", CheckUacAsync),
            ("SMBv1", CheckSmb1Async),
            ("RDP", CheckRdpAsync),
            ("Password Policy", CheckPasswordPolicyAsync),
            ("Local Administrator Accounts", CheckLocalAdminsAsync),
            ("PowerShell Logging", CheckPowerShellLoggingAsync),
            ("Windows Audit Policy", CheckAuditPolicyAsync),
            ("Backup Status", CheckBackupAsync),
        };

        foreach (var check in checks)
        {
            progress?.Report(check.Name);
            try { results.Add(await check.Run()); }
            catch (Exception ex)
            {
                results.Add(new AuditResult { Check = check.Name, Status = AuditStatus.Error, Severity = "Medium", Actual = ex.Message, Recommendation = "Review the audit permissions and Windows configuration." });
            }
        }

        return results;
    }

    private async Task<AuditResult> CheckDefenderAsync()
    {
        var output = await _ps.RunAsync("(Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled) 2>$null");
        var pass = output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
        return R("Windows Defender", pass ? AuditStatus.Pass : AuditStatus.Fail, "High", "Real-time protection enabled", output, "Enable Microsoft Defender real-time protection.");
    }

    private async Task<AuditResult> CheckFirewallAsync()
    {
        var output = await _ps.RunAsync("(Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled) -join ','");
        var pass = output.Split(',', StringSplitOptions.RemoveEmptyEntries).All(x => x.Trim().Equals("True", StringComparison.OrdinalIgnoreCase));
        return R("Windows Firewall", pass ? AuditStatus.Pass : AuditStatus.Fail, "High", "All firewall profiles enabled", output, "Enable Windows Firewall for all applicable profiles.");
    }

    private async Task<AuditResult> CheckBitLockerAsync()
    {
        var output = await _ps.RunAsync("(Get-BitLockerVolume -MountPoint $env:SystemDrive | Select-Object -ExpandProperty ProtectionStatus) 2>$null");
        var pass = output.Trim().Equals("On", StringComparison.OrdinalIgnoreCase) || output.Trim().Equals("1", StringComparison.OrdinalIgnoreCase);
        return R("BitLocker", pass ? AuditStatus.Pass : AuditStatus.Fail, "High", "System drive protection enabled", output, "Enable BitLocker on the system drive where organizational policy requires encryption.");
    }

    private async Task<AuditResult> CheckUacAsync()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
        var value = key?.GetValue("EnableLUA");
        var pass = Convert.ToInt32(value ?? 0) == 1;
        return R("UAC", pass ? AuditStatus.Pass : AuditStatus.Fail, "High", "EnableLUA = 1", $"EnableLUA = {value}", "Enable User Account Control.");
    }

    private async Task<AuditResult> CheckSmb1Async()
    {
        var output = await _ps.RunAsync("(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State");
        var pass = output.Trim().Equals("Disabled", StringComparison.OrdinalIgnoreCase);
        return R("SMBv1", pass ? AuditStatus.Pass : AuditStatus.Fail, "High", "SMBv1 disabled", output, "Disable SMBv1 unless a documented legacy requirement exists.");
    }

    private async Task<AuditResult> CheckRdpAsync()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
        var value = key?.GetValue("fDenyTSConnections");
        var pass = Convert.ToInt32(value ?? 1) == 1;
        return R("RDP", pass ? AuditStatus.Pass : AuditStatus.Warning, "Medium", "RDP disabled unless required", $"fDenyTSConnections = {value}", "Disable RDP if it is not required; otherwise restrict access and use Network Level Authentication.");
    }

    private async Task<AuditResult> CheckPasswordPolicyAsync()
    {
        var output = await _ps.RunAsync("net accounts");
        var hasHistory = output.Contains("Minimum password history", StringComparison.OrdinalIgnoreCase);
        return R("Password Policy", hasHistory ? AuditStatus.Pass : AuditStatus.Warning, "Medium", "Password policy is configured", Compact(output), "Review password length, age, history and lockout policy against your selected baseline.");
    }

    private async Task<AuditResult> CheckLocalAdminsAsync()
    {
        var output = await _ps.RunAsync("Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name");
        var count = output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length;
        var status = count <= 3 ? AuditStatus.Pass : AuditStatus.Warning;
        return R("Local Administrator Accounts", status, "Medium", "Only required administrator accounts", $"{count} members\n{output}", "Review administrator group membership and remove unnecessary privileged accounts.");
    }

    private async Task<AuditResult> CheckPowerShellLoggingAsync()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging");
        var value = key?.GetValue("EnableScriptBlockLogging");
        var pass = Convert.ToInt32(value ?? 0) == 1;
        return R("PowerShell Logging", pass ? AuditStatus.Pass : AuditStatus.Warning, "Medium", "Script Block Logging enabled", $"EnableScriptBlockLogging = {value}", "Enable PowerShell Script Block Logging according to organizational policy.");
    }

    private async Task<AuditResult> CheckAuditPolicyAsync()
    {
        var output = await _ps.RunAsync("auditpol /get /category:* 2>$null");
        var pass = output.Contains("Success and Failure", StringComparison.OrdinalIgnoreCase) || output.Contains("Success", StringComparison.OrdinalIgnoreCase);
        return R("Windows Audit Policy", pass ? AuditStatus.Pass : AuditStatus.Warning, "Medium", "Relevant audit categories configured", Compact(output), "Review Windows audit policy categories and enable appropriate success/failure auditing.");
    }

    private async Task<AuditResult> CheckBackupAsync()
    {
        var output = await _ps.RunAsync("$x = wbadmin get versions 2>$null; if ($LASTEXITCODE -eq 0) {$x} else {'No supported wbadmin backup evidence detected.'}");
        var pass = !output.Contains("No supported", StringComparison.OrdinalIgnoreCase) && output.Contains("Version identifier", StringComparison.OrdinalIgnoreCase);
        return R("Backup Status", pass ? AuditStatus.Pass : AuditStatus.Warning, "Medium", "Recent backup evidence detected", Compact(output), "Verify that an approved backup solution is configured and that recent backups completed successfully. Third-party backup products may require separate integration.");
    }

    private static AuditResult R(string check, AuditStatus status, string severity, string expected, string actual, string recommendation) => new()
    {
        Check = check, Status = status, Severity = severity, Expected = expected, Actual = actual, Evidence = actual, Recommendation = recommendation
    };

    private static string Compact(string text) => text.Length > 1200 ? text[..1200] + "..." : text;
}
