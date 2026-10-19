using System.IO;
using System.Text;
using System.Net;
using WindowsSecurityAudit.Models;

namespace WindowsSecurityAudit.Services;

public sealed class ReportService
{
    public string CreateHtmlReport(List<AuditResult> results)
    {
        var root = AppContext.BaseDirectory;
        var dir = Path.Combine(root, "Reports");
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, $"{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}_Audit.html");
        var score = CalculateScore(results);
        var risk = score >= 85 ? "Low" : score >= 70 ? "Medium" : "High";
        var sb = new StringBuilder();
        sb.AppendLine("<!doctype html><html><head><meta charset='utf-8'><title>Windows Security Audit Report</title>");
        sb.AppendLine("<style>body{font-family:Segoe UI,Arial;background:#f4f7fb;color:#172033;margin:40px}h1{color:#12263a}.card{background:white;padding:22px;border-radius:12px;margin:18px 0;box-shadow:0 2px 8px #0001}.score{font-size:42px;font-weight:700}.pass{color:#168a4a}.warning{color:#d97706}.fail{color:#c62828}table{width:100%;border-collapse:collapse}th,td{padding:10px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}</style></head><body>");
        sb.AppendLine($"<h1>Windows Security Audit Report</h1><div class='card'><b>Computer:</b> {WebUtility.HtmlEncode(Environment.MachineName)}<br/><b>Date:</b> {DateTime.Now}<br/><b>OS:</b> {WebUtility.HtmlEncode(Environment.OSVersion.VersionString)}<br/><div class='score'>{score}/100</div><b>Risk:</b> {risk}</div>");
        sb.AppendLine("<div class='card'><h2>Findings</h2><table><tr><th>Check</th><th>Status</th><th>Severity</th><th>Expected</th><th>Actual</th><th>Recommendation</th></tr>");
        foreach (var r in results)
        {
            var cls = r.Status.ToString().ToLowerInvariant();
            sb.AppendLine($"<tr><td>{E(r.Check)}</td><td class='{cls}'>{r.Status}</td><td>{E(r.Severity)}</td><td>{E(r.Expected)}</td><td><pre>{E(r.Actual)}</pre></td><td>{E(r.Recommendation)}</td></tr>");
        }
        sb.AppendLine("</table></div></body></html>");
        File.WriteAllText(file, sb.ToString(), Encoding.UTF8);
        return file;
    }

    public static int CalculateScore(List<AuditResult> results)
    {
        if (results.Count == 0) return 0;
        double total = 0;
        foreach (var r in results) total += r.Status switch { AuditStatus.Pass => 100, AuditStatus.Warning => 60, AuditStatus.Fail => 0, _ => 50 };
        return (int)Math.Round(total / results.Count);
    }

    private static string E(string s) => WebUtility.HtmlEncode(s ?? "");
}
