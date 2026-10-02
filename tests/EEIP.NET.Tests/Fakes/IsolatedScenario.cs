using System.Diagnostics;
using System.Text;

namespace EEIP.NET.Tests.Fakes;

/// <summary>
/// Some defects (an unhandled exception on a threadpool thread) terminate the process, which would take the whole
/// test run down with them. Such a scenario is written as a test method that skips itself unless
/// <see cref="EnvironmentVariable"/> names it, and a parent test runs it in a child process through this helper.
/// </summary>
public static class IsolatedScenario
{
    public const string EnvironmentVariable = "EEIP_TESTS_ISOLATED_SCENARIO";

    /// <summary>First line of the scenario: skips unless this is the child process launched for it.</summary>
    public static void SkipUnlessRequested(string scenario) =>
        Assert.SkipUnless(Environment.GetEnvironmentVariable(EnvironmentVariable) == scenario,
            $"child-process scenario '{scenario}'; it is launched by its parent test");

    /// <summary>Runs <paramref name="scenarioMethod"/> of <paramref name="scenarioType"/> in a fresh test host and fails the calling test if it crashes, fails or does not run.</summary>
    public static async Task AssertPassesAsync(Type scenarioType, string scenarioMethod, CancellationToken token)
    {
        var assembly = typeof(IsolatedScenario).Assembly.Location;
        var host = Environment.ProcessPath ?? "dotnet";
        var startInfo = new ProcessStartInfo(host)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        if (!Path.GetFileNameWithoutExtension(host).Equals(Path.GetFileNameWithoutExtension(assembly), StringComparison.OrdinalIgnoreCase))
        {
            if (!Path.GetFileNameWithoutExtension(host).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
                startInfo.FileName = "dotnet";
            startInfo.ArgumentList.Add(assembly);
        }
        startInfo.ArgumentList.Add("-noLogo");
        startInfo.ArgumentList.Add("-noColor");
        startInfo.ArgumentList.Add("-method");
        startInfo.ArgumentList.Add($"{scenarioType.FullName}.{scenarioMethod}");
        startInfo.Environment[EnvironmentVariable] = scenarioMethod;

        var output = new StringBuilder();
        using var process = new Process { StartInfo = startInfo };
        process.OutputDataReceived += (_, e) => { lock (output) output.AppendLine(e.Data); };
        process.ErrorDataReceived += (_, e) => { lock (output) output.AppendLine(e.Data); };
        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw;
        }
        process.WaitForExit(); // flush the redirected streams

        string log;
        lock (output) log = output.ToString();
        // xunit's crash handler prints "[FATAL ERROR]" for an unhandled exception on any thread, but the exit code is
        // 0 when the scenario happens to finish first, so the log is the reliable signal.
        Assert.False(log.Contains("[FATAL ERROR]"), $"Scenario {scenarioMethod} crashed the process:{Environment.NewLine}{log}");
        Assert.True(process.ExitCode == 0, $"Scenario {scenarioMethod} exited with code {process.ExitCode}:{Environment.NewLine}{log}");
        Assert.True(log.Contains("Total: 1,") && log.Contains("Failed: 0,") && log.Contains("Skipped: 0,"),
            $"Scenario {scenarioMethod} did not run exactly one test to success:{Environment.NewLine}{log}");
    }
}
