using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using PortScope.Models;

namespace PortScope.Services
{
    public class SslAnalyzer
    {
        public async Task<SslInfo?> AnalyzeAsync(string host, int port, int timeoutMs, CancellationToken ct)
        {
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(host, port).WaitAsync(TimeSpan.FromMilliseconds(timeoutMs), ct);

                using var sslStream = new SslStream(client.GetStream(), false,
                    (sender, cert, chain, errors) => true);

                await sslStream.AuthenticateAsClientAsync(host).WaitAsync(TimeSpan.FromMilliseconds(timeoutMs), ct);

                var cert = sslStream.RemoteCertificate as X509Certificate2
                    ?? new X509Certificate2(sslStream.RemoteCertificate!);

                var info = new SslInfo
                {
                    CommonName = GetCnFromSubject(cert.Subject),
                    Issuer = GetCnFromSubject(cert.Issuer),
                    ValidFrom = cert.NotBefore,
                    ValidTo = cert.NotAfter,
                    SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName ?? "Unknown",
                };

                foreach (var ext in cert.Extensions)
                {
                    if (ext.Oid?.Value == "2.5.29.17")
                    {
                        var sanText = ext.Format(true);
                        var sans = sanText.Split('\n');
                        info.SubjectAltNames = Array.ConvertAll(sans, s => s.Trim().Replace("DNS Name=", ""));
                    }
                }

                return info;
            }
            catch { return null; }
        }

        private string GetCnFromSubject(string subject)
        {
            foreach (var part in subject.Split(','))
            {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("CN="))
                    return trimmed[3..];
            }
            return subject;
        }
    }
}