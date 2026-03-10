using SoftwareSwitch;
using Xunit;

namespace SoftwareSwitch.Tests;

/// <summary>
/// Unit tests for <see cref="WebGui.ParseHexFrame"/> helper.
/// </summary>
public class WebGuiHelpersTests
{
    [Fact]
    public void ParseHexFrame_AcceptsWhitespace()
    {
        byte[] result = WebGui.ParseHexFrame("00 11 22\n33 44 55");
        Assert.Equal(new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }, result);
    }

    [Fact]
    public void ParseHexFrame_RejectsOddLength()
    {
        var ex = Assert.Throws<ArgumentException>(() => WebGui.ParseHexFrame("001"));
        Assert.Contains("even number", ex.Message);
    }

    [Fact]
    public void ParseHexFrame_RejectsInvalidHex()
    {
        var ex = Assert.Throws<ArgumentException>(() => WebGui.ParseHexFrame("gg"));
        Assert.Contains("invalid hexadecimal", ex.Message);
    }
}
