using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using PortScope.Models;

namespace PortScope.Services
{
    public class IcmpScanner
    {
        public async Task<(bool isAlive, int ttl, long roundtripMs)> PingHostAsync(string host, int timeoutMs, CancellationToken ct)
        {
            try
            {
                using var ping = new Ping();
                var options = new PingOptions { DontFragment = true };
                byte[] buffer = new byte[32];
                new Random().NextBytes(buffer);

                var reply = await ping.SendPingAsync(host, timeoutMs, buffer, options);

                if (reply.Status == IPStatus.Success)
                    return (true, reply.Options?.Ttl ?? 0, reply.RoundtripTime);
                return (false, 0, 0);
            }
            catch { return (false, 0, 0); }
        }

        public async Task<List<(string host, bool isAlive, int ttl, long ms)>> PingSweepAsync(
            string network, int cidr,
            IProgress<(int scanned, int total, string host, bool isAlive)>? progress,
            CancellationToken ct)
        {
            var hosts = GetHostsFromCidr(network, cidr);
            var results = new System.Collections.Concurrent.ConcurrentBag<(string, bool, int, long)>();
            int total = hosts.Count;
            int scanned = 0;

            var semaphore = new SemaphoreSlim(100);
            var tasks = new List<Task>();

            foreach (var host in hosts)
            {
                if (ct.IsCancellationRequested) break;
                string h = host;
                await semaphore.WaitAsync(ct);

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var (alive, ttl, ms) = await PingHostAsync(h, 1000, ct);
                        results.Add((h, alive, ttl, ms));
                        int s = Interlocked.Increment(ref scanned);
                        progress?.Report((s, total, h, alive));
                    }
                    finally { semaphore.Release(); }
                }, ct));
            }

            await Task.WhenAll(tasks);
            return new List<(string, bool, int, long)>(results);
        }

        private static List<string> GetHostsFromCidr(string network, int cidr)
        {
            var hosts = new List<string>();
            try
            {
                var baseIp = IPAddress.Parse(network);
                var bytes = baseIp.GetAddressBytes();
                uint ipInt = (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
                uint mask = cidr == 0 ? 0 : (uint)(0xFFFFFFFF << (32 - cidr));
                uint networkAddr = ipInt & mask;
                uint broadcastAddr = networkAddr | ~mask;

                for (uint i = networkAddr + 1; i < broadcastAddr; i++)
                {
                    var b = new byte[] { (byte)(i >> 24), (byte)(i >> 16), (byte)(i >> 8), (byte)i };
                    hosts.Add(new IPAddress(b).ToString());
                }
            }
            catch { }
            return hosts;
        }

        public static (string network, int cidr) ParseCidr(string input)
        {
            var parts = input.Split('/');
            return (parts[0], parts.Length > 1 ? int.Parse(parts[1]) : 32);
        }
    }
}