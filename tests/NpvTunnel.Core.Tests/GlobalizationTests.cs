using System.Globalization;
using Xunit;

namespace NpvTunnel.Core.Tests;

/// <summary>
/// Guards the globalization mode. 1.0.0 shipped with
/// <c>InvariantGlobalization=true</c>; the WPF shell resolves cultures while it
/// renders its own templates, so the first window threw
/// <c>CultureNotFoundException: Cannot find non-neutral culture related to 'en-us'</c>
/// and the app died on launch. These tests fail the build if invariant mode ever
/// comes back, on any project that shares Directory.Build.props.
/// </summary>
public sealed class GlobalizationTests
{
    [Fact]
    public void InvariantMode_IsOff()
    {
        bool enabled = AppContext.TryGetSwitch("System.Globalization.Invariant", out bool value) && value;

        Assert.False(enabled, "InvariantGlobalization must stay false: WPF cannot render without real culture data.");
    }

    [Fact]
    public void SpecificCultures_AreAvailable()
    {
        CultureInfo culture = CultureInfo.GetCultureInfo("en-US");

        Assert.Equal("en-US", culture.Name);
        Assert.NotEqual(CultureInfo.InvariantCulture.Name, culture.Name);
    }

    [Fact]
    public void CultureSensitiveFormatting_ProducesCultureData()
    {
        var when = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);

        string us = when.ToString("MMM d, yyyy HH:mm", CultureInfo.GetCultureInfo("en-US"));
        string de = when.ToString("MMM d, yyyy HH:mm", CultureInfo.GetCultureInfo("de-DE"));

        Assert.Contains("Jan", us, StringComparison.Ordinal);
        Assert.NotEqual(us, de);
    }
}
