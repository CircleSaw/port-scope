using System.Net.NetworkInformation;
using System.Threading.Tasks;
using PortScope.Models;

namespace PortScope.Services
{
    public class OsFingerprinter
    {
        public async Task<string> DetectOsAsync(string host, int ttl)
        {
            // TTL bazlı OS tespiti
            if (ttl == 0)
            {
                // ICMP ping yaparak TTL al
                try
                {
                    using var ping = new System.Net.NetworkInformation.Ping();
                    var reply = await ping.SendPingAsync(host, 2000);
                    if (reply.Status == IPStatus.Success)
                        ttl = reply.Options?.Ttl ?? 0;
                }
                catch { }
            }

            string ttlGuess = ttl switch
            {
                > 0 and <= 64 => "Linux/Unix (TTL ~64)",
                > 64 and <= 128 => "Windows (TTL ~128)",
                > 128 and <= 255 => "Cisco/Network Device (TTL ~255)",
                _ => "Unknown"
            };

            // Port bazlı tahmin
            return ttlGuess;
        }

        public string RefineOsGuess(string ttlGuess, List<PortInfo> openPorts)
        {
            var portNums = openPorts.ConvertAll(p => p.Port);

            bool hasRdp = portNums.Contains(3389);
            bool hasMsrpc = portNums.Contains(135);
            bool hasSmb = portNums.Contains(445);
            bool hasSsh = portNums.Contains(22);

            // Hem RDP hem SMB varsa Windows
            if (hasRdp && hasSmb)
                return "Windows Server/Desktop (RDP/SMB detected)";

            // Sadece SMB veya MSRPC yetmez
            if (hasSsh && !hasRdp && !hasSmb)
                return ttlGuess.Contains("Linux")
                    ? "Linux/Unix (SSH detected)"
                    : ttlGuess;

            return ttlGuess;
        }
    }
}