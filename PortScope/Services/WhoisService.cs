using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using PortScope.Models;

namespace PortScope.Services
{
    public class WhoisService
    {
        private static readonly string[] WhoisServers =
        {
            "whois.iana.org",
            "whois.verisign-grs.com",
            "whois.internic.net"
        };

        public async Task<WhoisInfo> QueryAsync(string domain, CancellationToken ct)
        {
            string rawData = "";
            domain = domain.Trim().ToLower();

            // IP mi domain mi
            bool isIp = System.Net.IPAddress.TryParse(domain, out _);

            try
            {
                if (isIp)
                {
                    rawData = await QueryServerAsync("whois.arin.net", domain, ct);
                }
                else
                {
                    var parts = domain.Split('.');
                    if (parts.Length > 2)
                        domain = string.Join(".", parts[^2], parts[^1]);

                    string tld = domain.Split('.').Last();
                    string server = tld switch
                    {
                        "com" or "net" => "whois.verisign-grs.com",
                        "org" => "whois.pir.org",
                        "io" => "whois.nic.io",
                        "tr" => "whois.nic.tr",
                        _ => "whois.iana.org"
                    };

                    rawData = await QueryServerAsync(server, domain, ct);

                    // Eğer IANAdan gerçek server geldiyse tekrar sorgula
                    if (server == "whois.iana.org" && rawData.Contains("whois:"))
                    {
                        var match = System.Text.RegularExpressions.Regex.Match(
                            rawData, @"whois:\s+(\S+)",
                            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                        if (match.Success)
                            rawData = await QueryServerAsync(match.Groups[1].Value.Trim(), domain, ct);
                    }
                }

            }
            catch (Exception ex)
            {
                rawData = $"WHOIS Error: {ex.Message}";
            }

            return ParseWhois(rawData, domain);
        }

        private async Task<string> QueryServerAsync(string server, string query, CancellationToken ct)
        {
            using var client = new TcpClient();
            await client.ConnectAsync(server, 43).WaitAsync(TimeSpan.FromSeconds(20), ct);

            using var stream = client.GetStream();

            // Tüm sunucular için sadece düz domain adı gönder
            var queryBytes = Encoding.ASCII.GetBytes(query + "\r\n");
            await stream.WriteAsync(queryBytes, 0, queryBytes.Length, ct);

            using var reader = new StreamReader(stream, Encoding.ASCII);
            return await reader.ReadToEndAsync();
        }

        private WhoisInfo ParseWhois(string raw, string domain)
        {
            var info = new WhoisInfo { RawData = raw };

            info.Organization = ExtractField(raw, new[] { "Organization:", "org-name:", "OrgName:", "owner:" });
            info.Country = ExtractField(raw, new[] { "Country:", "country:" });
            info.Registrar = ExtractField(raw, new[] { "Registrar:", "registrar:" });
            info.CreatedDate = ExtractField(raw, new[] { "Creation Date:", "created:", "RegDate:" });
            info.ExpiryDate = ExtractField(raw, new[] { "Expiry Date:", "expires:", "Expiration Date:" });

            var nsMatches = Regex.Matches(raw, @"Name Server:\s*(\S+)", RegexOptions.IgnoreCase);
            if (nsMatches.Count > 0)
            {
                info.NameServers = new string[nsMatches.Count];
                for (int i = 0; i < nsMatches.Count; i++)
                    info.NameServers[i] = nsMatches[i].Groups[1].Value;
            }

            return info;
        }

        private string ExtractField(string raw, string[] keys)
        {
            foreach (var key in keys)
            {
                var match = Regex.Match(raw, key + @"\s*(.+)", RegexOptions.IgnoreCase);
                if (match.Success)
                    return match.Groups[1].Value.Trim();
            }
            return "";
        }
    }
}