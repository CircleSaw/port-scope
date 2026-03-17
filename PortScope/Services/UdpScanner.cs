using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using PortScope.Models;

namespace PortScope.Services
{
    public class UdpScanner
    {
        private static readonly Dictionary<int, byte[]> UdpProbes = new()
        {
            { 53,  new byte[] { 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01 } }, // DNS
            { 161, new byte[] { 0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63 } }, // SNMP
            { 123, new byte[] { 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }, // NTP
        };

        public async Task<PortInfo> ScanPortAsync(string host, int port, int timeoutMs, CancellationToken ct)
        {
            var portInfo = new PortInfo { Port = port, Protocol = "UDP" };

            await Task.Run(async () =>
            {
                try
                {
                    using var udpClient = new UdpClient();
                    udpClient.Client.ReceiveTimeout = timeoutMs;
                    udpClient.Client.SendTimeout = timeoutMs;

                    var probe = UdpProbes.TryGetValue(port, out var p) ? p : new byte[] { 0x00 };
                    await udpClient.SendAsync(probe, probe.Length, host, port);

                    try
                    {
                        var result = await udpClient.ReceiveAsync().WaitAsync(TimeSpan.FromMilliseconds(timeoutMs), ct);
                        portInfo.State = PortState.Open;
                        portInfo.ServiceName = WellKnownPorts.GetServiceName(port);
                    }
                    catch (TimeoutException)
                    {
                        // UDP timeout = open - filtered
                        portInfo.State = PortState.OpenFiltered;
                    }
                }
                catch (SocketException ex)
                {
                    // ICMP port unreachable = closed
                    portInfo.State = ex.SocketErrorCode == SocketError.ConnectionReset
                        ? PortState.Closed : PortState.Filtered;
                }
                catch { portInfo.State = PortState.Filtered; }
            }, ct);

            return portInfo;
        }

        public async Task<List<PortInfo>> ScanRangeAsync(
            string host, int startPort, int endPort, int timeoutMs, int maxThreads,
            IProgress<(int scanned, int total, PortInfo? result)>? progress,
            CancellationToken ct)
        {
            var results = new System.Collections.Concurrent.ConcurrentBag<PortInfo>();
            int total = endPort - startPort + 1;
            int scanned = 0;
            var semaphore = new SemaphoreSlim(Math.Min(maxThreads, 50));
            var tasks = new List<Task>();

            for (int port = startPort; port <= endPort; port++)
            {
                if (ct.IsCancellationRequested) break;
                int p = port;
                await semaphore.WaitAsync(ct);

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var info = await ScanPortAsync(host, p, timeoutMs, ct);
                        results.Add(info);
                        int s = Interlocked.Increment(ref scanned);
                        progress?.Report((s, total, info.State != PortState.Closed ? info : null));
                    }
                    finally { semaphore.Release(); }
                }, ct));
            }

            await Task.WhenAll(tasks);
            return new List<PortInfo>(results);
        }
    }
}