using System;
using System.Collections.Generic;

namespace PortScope.Models
{
    public class ScanResult
    {
        public string TargetHost { get; set; } = "";
        public string ResolvedIp { get; set; } = "";
        public string OsGuess { get; set; } = "";
        public int Ttl { get; set; }
        public bool IsAlive { get; set; }
        public WhoisInfo? WhoisData { get; set; }
        public List<PortInfo> Ports { get; set; } = new();
        public DateTime ScanStarted { get; set; }
        public DateTime ScanFinished { get; set; }
        public ScanType ScanMethod { get; set; }
        public TimeSpan Duration => ScanFinished - ScanStarted;
        public int OpenPortCount => Ports.FindAll(p => p.State == PortState.Open).Count;
    }

    public class WhoisInfo
    {
        public string RawData { get; set; } = "";
        public string Organization { get; set; } = "";
        public string Country { get; set; } = "";
        public string Registrar { get; set; } = "";
        public string CreatedDate { get; set; } = "";
        public string ExpiryDate { get; set; } = "";
        public string[] NameServers { get; set; } = Array.Empty<string>();
    }
}