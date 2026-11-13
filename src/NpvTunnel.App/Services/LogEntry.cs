using System;

namespace NpvTunnel.App.Services;

public sealed record LogEntry(DateTimeOffset Timestamp, LogLevel Level, string Source, string Message)
{
    public string Time => Timestamp.ToLocalTime().ToString("HH:mm:ss");

    public string LevelText => Level switch
    {
        LogLevel.Debug => "DBG",
        LogLevel.Info => "INF",
        LogLevel.Warn => "WRN",
        _ => "ERR",
    };

    public override string ToString()
    {
        return $"{Timestamp.ToLocalTime():yyyy-MM-dd HH:mm:ss} [{LevelText}] {Source}: {Message}";
    }
}
