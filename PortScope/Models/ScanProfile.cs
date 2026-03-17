using System;
using System.Collections.Generic;

namespace PortScope.Models
{
    public class ScanProfile
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public string TargetHost { get; set; } = "";
        public string PortRange { get; set; } = "1-1024";
        public string CustomPorts { get; set; } = "";
        public ScanType ScanMethod { get; set; } = ScanType.TCP;
        public int TimeoutMs { get; set; } = 1000;
        public int RetryCount { get; set; } = 1;
        public int ThreadCount { get; set; } = 200;
        public bool EnableBannerGrab { get; set; } = true;
        public bool EnableOsDetection { get; set; } = true;
        public bool EnableSslAnalysis { get; set; } = true;
        public bool EnableWhois { get; set; } = true;
        public DateTime CreatedAt { get; set; } = DateTime.Now;

        // Profiller
        public static ScanProfile QuickScan => new()
        {
            Name = "Quick Scan",
            Description = "En yaygın 100 portu hızlıca tara",
            PortRange = "1-1024",
            TimeoutMs = 500,
            ThreadCount = 500,
            EnableBannerGrab = false,
            EnableOsDetection = false
        };

        public static ScanProfile FullScan => new()
        {
            Name = "Full Scan",
            Description = "Tüm portları detaylı tara",
            PortRange = "1-65535",
            TimeoutMs = 2000,
            ThreadCount = 200,
            EnableBannerGrab = true,
            EnableOsDetection = true
        };

        public static ScanProfile StealthScan => new()
        {
            Name = "Stealth SYN Scan",
            Description = "SYN paketi ile sessiz tarama",
            PortRange = "1-1024",
            ScanMethod = ScanType.SYN,
            TimeoutMs = 1500,
            ThreadCount = 100
        };

        public static List<ScanProfile> DefaultProfiles =>
            new() { QuickScan, FullScan, StealthScan };
    }
}