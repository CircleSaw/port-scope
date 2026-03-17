using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using PortScope.Models;

namespace PortScope.Services
{
    public class TcpScanner
    {
        public async Task<PortInfo> ScanPortAsync(string host, int port, int timeoutMs, int retryCount, CancellationToken ct)
        {
            var portInfo = new PortInfo { Port = port, Protocol = "TCP" };
            var sw = Stopwatch.StartNew();

            for (int attempt = 0; attempt <= retryCount; attempt++)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    using var client = new TcpClient();
                    client.LingerState = new System.Net.Sockets.LingerOption(true, 0);

                    var connectTask = client.ConnectAsync(host, port);
                    var timeoutTask = Task.Delay(timeoutMs, ct);

                    if (await Task.WhenAny(connectTask, timeoutTask) == connectTask)
                    {
                        if (connectTask.IsCompletedSuccessfully && client.Connected)
                        {
                            sw.Stop();
                            portInfo.State = PortState.Open;
                            portInfo.ResponseTimeMs = sw.ElapsedMilliseconds;
                            portInfo.ServiceName = WellKnownPorts.GetServiceName(port);
                            return portInfo;
                        }
                        else
                        {
                            // Bağlantı tamamlandı ama başarısız
                            portInfo.State = PortState.Closed;
                        }
                    }
                    else
                    {
                        // Timeout
                        portInfo.State = PortState.Filtered;
                    }
                }
                catch (SocketException ex)
                {
                    portInfo.State = ex.SocketErrorCode == SocketError.ConnectionRefused
                        ? PortState.Closed
                        : PortState.Filtered;
                }
                catch { portInfo.State = PortState.Filtered; }
            }

            sw.Stop();
            portInfo.ResponseTimeMs = sw.ElapsedMilliseconds;
            return portInfo;
        }

        public async Task<List<PortInfo>> ScanRangeAsync(
            string host, int startPort, int endPort,
            int timeoutMs, int retryCount, int maxThreads,
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
                int capturedPort = port;
                await semaphore.WaitAsync(ct);

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var info = await ScanPortAsync(host, capturedPort, timeoutMs, retryCount, ct);
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