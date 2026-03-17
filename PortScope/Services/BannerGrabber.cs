using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PortScope.Models;

namespace PortScope.Services
{
    public class BannerGrabber
    {
        private static readonly int BufferSize = 4096;

        // Porta özgü probe mesajları
        private static string GetProbe(int port) => port switch
        {
            21 => "",               // FTP banner
            22 => "",               // SSH banner
            25 => "EHLO nexscan\r\n",
            80 => "HEAD / HTTP/1.0\r\nHost: {0}\r\n\r\n",
            110 => "",              // POP3
            143 => "",              // IMAP
            443 => "HEAD / HTTP/1.0\r\nHost: {0}\r\n\r\n",
            3306 => "",             // MySQL
            5432 => "",             // PostgreSQL için özel handshake
            6379 => "INFO\r\n",    // Redis
            _ => "\r\n"
        };

        public async Task<string> GrabAsync(string host, int port, int timeoutMs, CancellationToken ct)
        {
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(host, port).WaitAsync(TimeSpan.FromMilliseconds(timeoutMs), ct);
                client.ReceiveTimeout = timeoutMs;
                client.SendTimeout = timeoutMs;

                using var stream = client.GetStream();
                var buffer = new byte[BufferSize];

                // Önce gelen bannerı oku
                string banner = "";
                if (stream.CanRead)
                {
                    var readTask = stream.ReadAsync(buffer, 0, buffer.Length, ct);
                    if (await Task.WhenAny(readTask, Task.Delay(Math.Min(timeoutMs, 2000), ct)) == readTask)
                    {
                        int read = await readTask;
                        if (read > 0)
                            banner = Encoding.ASCII.GetString(buffer, 0, read).Trim();
                    }
                }

                // Probe gönder
                string probe = string.Format(GetProbe(port), host);
                if (!string.IsNullOrEmpty(probe))
                {
                    var probeBytes = Encoding.ASCII.GetBytes(probe);
                    await stream.WriteAsync(probeBytes, 0, probeBytes.Length, ct);

                    var readTask2 = stream.ReadAsync(buffer, 0, buffer.Length, ct);
                    if (await Task.WhenAny(readTask2, Task.Delay(Math.Min(timeoutMs, 2000), ct)) == readTask2)
                    {
                        int read = await readTask2;
                        if (read > 0)
                            banner += "\n" + Encoding.ASCII.GetString(buffer, 0, read).Trim();
                    }
                }

                return banner.Trim();
            }
            catch { return ""; }
        }

        public string ParseVersion(string banner, int port)
        {
            if (string.IsNullOrEmpty(banner)) return "";

            // Servise göre versiyon parse et
            return port switch
            {
                22 => ExtractSsh(banner),
                21 => ExtractFtp(banner),
                25 or 587 => ExtractSmtp(banner),
                80 or 8080 or 443 or 8443 => ExtractHttp(banner),
                3306 => ExtractMysql(banner),
                6379 => ExtractRedis(banner),
                _ => banner.Length > 100 ? banner[..100] : banner
            };
        }

        private string ExtractSsh(string b) =>
            b.Contains("SSH-") ? b.Split('\n')[0] : b;

        private string ExtractFtp(string b) =>
            b.Split('\n')[0];

        private string ExtractSmtp(string b)
        {
            foreach (var line in b.Split('\n'))
                if (line.Contains("220 ")) return line.Trim();
            return b.Split('\n')[0];
        }

        private string ExtractHttp(string b)
        {
            string server = "";
            foreach (var line in b.Split('\n'))
            {
                if (line.StartsWith("Server:", StringComparison.OrdinalIgnoreCase))
                    server = line.Replace("Server:", "").Trim();
            }
            return server.Length > 0 ? server : b.Split('\n')[0];
        }

        private string ExtractMysql(string b)
        {
            // MySQL handshake versiyon çıkar
            if (b.Length > 5)
            {
                int nullPos = b.IndexOf('\0', 4);
                if (nullPos > 4)
                    return "MySQL " + b[4..nullPos];
            }
            return "MySQL";
        }

        private string ExtractRedis(string b) =>
            b.Contains("redis_version") ?
                b.Split('\n')[1].Replace("redis_version:", "Redis ").Trim() : b;
    }
}