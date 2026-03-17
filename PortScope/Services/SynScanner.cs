using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using PortScope.Models;

namespace PortScope.Services
{
    public class SynScanner
    {
        public async Task<PortInfo> ScanPortAsync(string host, int port, int timeoutMs, CancellationToken ct)
        {
            var portInfo = new PortInfo { Port = port, Protocol = "TCP/SYN" };

            await Task.Run(() =>
            {
                try
                {
                    using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    socket.Blocking = false;
                    socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendTimeout, timeoutMs);
                    socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, timeoutMs);

                    var endpoint = new IPEndPoint(Dns.GetHostAddresses(host)[0], port);
                    var result = socket.BeginConnect(endpoint, null, null);
                    bool success = result.AsyncWaitHandle.WaitOne(timeoutMs, true);

                    if (success && !socket.Connected)
                    {
                        portInfo.State = PortState.Closed;
                    }
                    else if (success && socket.Connected)
                    {
                        portInfo.State = PortState.Open;
                        portInfo.ServiceName = WellKnownPorts.GetServiceName(port);
                        socket.LingerState = new LingerOption(true, 0);
                    }
                    else
                    {
                        portInfo.State = PortState.Filtered;
                    }
                    socket.Close();
                }
                catch (SocketException ex)
                {
                    portInfo.State = ex.SocketErrorCode == SocketError.ConnectionRefused
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
            var semaphore = new SemaphoreSlim(maxThreads);
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
                        progress?.Report((s, total, info.State == PortState.Open ? info : null));
                    }
                    finally { semaphore.Release(); }
                }, ct));
            }

            await Task.WhenAll(tasks);
            return new List<PortInfo>(results);
        }
    }
}