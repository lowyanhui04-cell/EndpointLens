using System.IO;
using System.Diagnostics;
using System.Security.Principal;
using System.Windows;
using WindowsSecurityAudit.Models;
using WindowsSecurityAudit.Services;

namespace WindowsSecurityAudit;

public partial class MainWindow : Window
{
    private readonly AuditEngine _engine = new();
    private readonly ReportService _reports = new();
    private string? _latestReport;
    private List<AuditResult> _results = new();

    public MainWindow()
    {
        InitializeComponent();
        ComputerText.Text = $"Computer Name: {Environment.MachineName}";
        OsText.Text = $"Operating System: {Environment.OSVersion.VersionString}";
        AdminText.Text = IsAdmin() ? "✓ Administrator privileges" : "⚠ Administrator privileges required";
    }

    private async void StartAudit_Click(object sender, RoutedEventArgs e)
    {
        StartButton.IsEnabled = false;
        ReportButton.IsEnabled = false;
        Progress.Value = 0;
        ProgressText.Text = "Starting audit...";

        var progress = new Progress<string>(name =>
        {
            ProgressText.Text = $"Checking: {name}";
            Progress.Value = Math.Min(95, Progress.Value + 8);
        });

        try
        {
            _results = await _engine.RunAsync(progress);
            Progress.Value = 100;
            ProgressText.Text = "Audit completed. Generating report...";
            _latestReport = _reports.CreateHtmlReport(_results);

            var score = ReportService.CalculateScore(_results);
            ScoreText.Text = $"Score: {score}/100";
            PassText.Text = $"PASS: {_results.Count(x => x.Status == AuditStatus.Pass)}";
            WarningText.Text = $"WARNING: {_results.Count(x => x.Status == AuditStatus.Warning)}";
            FailText.Text = $"FAIL: {_results.Count(x => x.Status == AuditStatus.Fail)}";
            ReportButton.IsEnabled = true;
            ProgressText.Text = $"Audit completed. Report saved to: {_latestReport}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Audit Error", MessageBoxButton.OK, MessageBoxImage.Error);
            ProgressText.Text = "Audit failed.";
        }
        finally { StartButton.IsEnabled = true; }
    }

    private void Report_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(_latestReport) && File.Exists(_latestReport))
            Process.Start(new ProcessStartInfo(_latestReport) { UseShellExecute = true });
    }

    private void Home_Click(object sender, RoutedEventArgs e) { }
    private void Audit_Click(object sender, RoutedEventArgs e) => StartAudit_Click(sender, e);
    private void Results_Click(object sender, RoutedEventArgs e) => ShowResults();
    private void Reports_Click(object sender, RoutedEventArgs e) => Report_Click(sender, e);

    private void ShowResults()
    {
        if (_results.Count == 0) { MessageBox.Show("Run an audit first."); return; }
        var text = string.Join(Environment.NewLine, _results.Select(r => $"{r.Status,-12} {r.Check} - {r.Actual.Replace(Environment.NewLine, " ")}"));
        MessageBox.Show(text, "Audit Results");
    }

    private static bool IsAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}
