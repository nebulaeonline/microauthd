using microauthd.Config;
using Serilog;
using System.Runtime.InteropServices;

namespace microauthd.Logging;

public static class LogSetup
{
    /// <summary>
    /// Initializes the logging system with the specified application configuration.
    /// </summary>
    /// <remarks>If the <see cref="AppConfig.LogFile"/> property is set to "microauthd.log", the log file path
    /// is determined  dynamically using an internal method. Otherwise, the specified log file path is used. The logger
    /// writes log messages to both the console and a rolling file, with a maximum file size of 10 MB  and a retention
    /// limit of 10 files.</remarks>
    /// <param name="config">The application configuration containing logging settings, including the log file path.</param>
    public static void Initialize(AppConfig config)
    {
        string logPath = "";

        if (config.LogFile.Trim().Length == 0)
            logPath = "microauthd.log";
        else
            logPath = config.LogFile.Trim();

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Debug()
            .WriteTo.Console()
            .WriteTo.File(
                logPath,
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 10,
                outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}",
                fileSizeLimitBytes: 10 * 1024 * 1024 // 10 MB per file
            )
            .CreateLogger();

        Log.Information("Logger initialized. Writing to: {Path}", logPath);
    }
}
