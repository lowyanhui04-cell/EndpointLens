namespace WindowsSecurityAudit.Models;

public enum AuditStatus { Pass, Warning, Fail, NotDetected, Error }

public sealed class AuditResult
{
    public string Check { get; init; } = "";
    public AuditStatus Status { get; init; }
    public string Severity { get; init; } = "";
    public string Expected { get; init; } = "";
    public string Actual { get; init; } = "";
    public string Evidence { get; init; } = "";
    public string Recommendation { get; init; } = "";
    public string Standard { get; init; } = "CIS / Windows Security Baseline (custom mapping)";
}
