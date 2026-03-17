using PortScope.Models;
using PortScope.Services;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace PortScope.ViewModels
{
    public class MainViewModel : INotifyPropertyChanged
    {
        // Services
        private readonly TcpScanner _tcpScanner = new();
        private readonly SynScanner _synScanner = new();
        private readonly UdpScanner _udpScanner = new();
        private readonly IcmpScanner _icmpScanner = new();
        private readonly BannerGrabber _bannerGrabber = new();
        private readonly OsFingerprinter _osFinger = new();
        private readonly SslAnalyzer _sslAnalyzer = new();
        private readonly WhoisService _whoisService = new();
        private readonly ReportExporter _exporter = new();

        private CancellationTokenSource? _cts;

        // Properties
        private string _targetHost = "";
        public string TargetHost { get => _targetHost; set => Set(ref _targetHost, value); }

        private string _portRange = "1-1024";
        public string PortRange { get => _portRange; set => Set(ref _portRange, value); }

        private string _customPorts = "";
        public string CustomPorts { get => _customPorts; set => Set(ref _customPorts, value); }

        private ScanType _scanMethod = ScanType.TCP;
        public ScanType ScanMethod { get => _scanMethod; set => Set(ref _scanMethod, value); }

        private int _timeoutMs = 1000;
        public int TimeoutMs { get => _timeoutMs; set => Set(ref _timeoutMs, value); }

        private int _retryCount = 1;
        public int RetryCount { get => _retryCount; set => Set(ref _retryCount, value); }

        private int _threadCount = 300;
        public int ThreadCount { get => _threadCount; set => Set(ref _threadCount, value); }

        private bool _enableBanner = true;
        public bool EnableBanner { get => _enableBanner; set => Set(ref _enableBanner, value); }

        private bool _enableOsDetection = true;
        public bool EnableOsDetection { get => _enableOsDetection; set => Set(ref _enableOsDetection, value); }

        private bool _enableSsl = true;
        public bool EnableSsl { get => _enableSsl; set => Set(ref _enableSsl, value); }

        private bool _enableWhois = true;
        public bool EnableWhois { get => _enableWhois; set => Set(ref _enableWhois, value); }

        private bool _isScanning = false;
        public bool IsScanning { get => _isScanning; set { Set(ref _isScanning, value); OnPropertyChanged(nameof(CanScan)); } }

        public bool CanScan => !IsScanning;

        private double _progress = 0;
        public double Progress { get => _progress; set => Set(ref _progress, value); }

        private string _statusText = "Hazır";
        public string StatusText { get => _statusText; set => Set(ref _statusText, value); }

        private string _scanStats = "";
        public string ScanStats { get => _scanStats; set => Set(ref _scanStats, value); }

        private int _openPortCount = 0;
        public int OpenPortCount { get => _openPortCount; set => Set(ref _openPortCount, value); }

        private int _scannedPortCount = 0;
        public int ScannedPortCount { get => _scannedPortCount; set => Set(ref _scannedPortCount, value); }

        private int _scanMethodIndex = 0;
        public int ScanMethodIndex
        {
            get => _scanMethodIndex;
            set
            {
                Set(ref _scanMethodIndex, value);
                ScanMethod = value switch
                {
                    0 => ScanType.TCP,
                    1 => ScanType.SYN,
                    2 => ScanType.UDP,
                    _ => ScanType.TCP
                };
            }
        }

        public ObservableCollection<PortInfo> OpenPorts { get; } = new();
        public ObservableCollection<string> Logs { get; } = new();
        public ObservableCollection<ScanProfile> SavedProfiles { get; } = new();
        public ObservableCollection<ScanResult> ScanHistory { get; } = new();
        public ObservableCollection<PortInfo> SslPorts { get; } = new();

        private ScanResult? _currentResult;
        public ScanResult? CurrentResult
        {
            get => _currentResult;
            private set => Set(ref _currentResult, value);
        }

        private List<ScanResult> AllResults { get; } = new();

        public MainViewModel()
        {
            LoadDefaultProfiles();
            LoadHistoryFromDisk();
        }

        // Scan
        public async Task StartScanAsync()
        {
            if (string.IsNullOrWhiteSpace(TargetHost))
            {
                AddLog("Hedef host/IP boş olamaz!");
                return;
            }

            // URL temizleme
            string target = TargetHost.Trim()
                .Replace("https://", "")
                .Replace("http://", "")
                .TrimEnd('/');
            if (target.Contains("/"))
                target = target.Split('/')[0];

            IsScanning = true;
            _cts = new CancellationTokenSource();
            var ct = _cts.Token;
            var sw = System.Diagnostics.Stopwatch.StartNew();

            OpenPorts.Clear();
            SslPorts.Clear();
            OpenPortCount = 0;
            ScannedPortCount = 0;
            Progress = 0;
            AllResults.Clear();

            try
            {
                // 1. DNS Çözümleme
                string resolvedIp = await ResolveHostAsync(target);
                AddLog($"DNS: {target} → {resolvedIp}");

                // 2. ICMP Ping
                AddLog("ICMP ping gönderiliyor...");
                var (isAlive, ttl, pingMs) = await _icmpScanner.PingHostAsync(resolvedIp, TimeoutMs, ct);
                AddLog(isAlive
                    ? $"Host aktif — TTL: {ttl}, Ping: {pingMs}ms"
                    : $"Host ping'e yanıt vermedi (firewall olabilir, taramaya devam)");

                // 3. OS Tahmini (TTL bazlı)
                string osGuess = "";
                if (EnableOsDetection)
                {
                    osGuess = await _osFinger.DetectOsAsync(resolvedIp, ttl);
                    AddLog($"OS Tahmini (TTL={ttl}): {osGuess}");
                }

                // 4. WHOIS
                WhoisInfo? whois = null;
                if (EnableWhois)
                {
                    AddLog("WHOIS sorgulanıyor...");
                    try
                    {
                        whois = await _whoisService.QueryAsync(target, ct);
                        if (!string.IsNullOrEmpty(whois.Organization))
                            AddLog($"Org: {whois.Organization} | Ülke: {whois.Country}");
                        AddLog($"Registrar: {whois.Registrar}");
                    }
                    catch { AddLog("WHOIS alınamadı"); }
                }

                // 5. Port listesini hazırla
                var ports = GetPortList();
                int total = ports.Count;
                AddLog($"{ScanMethod} taraması başlıyor... {total} port, {ThreadCount} thread");

                CurrentResult = new ScanResult
                {
                    TargetHost = target,
                    ResolvedIp = resolvedIp,
                    IsAlive = isAlive,
                    Ttl = ttl,
                    OsGuess = osGuess,
                    WhoisData = whois,
                    ScanMethod = ScanMethod,
                    ScanStarted = DateTime.Now
                };
                OnPropertyChanged(nameof(CurrentResult));

                // 6. Port Taraması
                var portProgress = new Progress<(int scanned, int total, PortInfo? result)>(rep =>
                {
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        ScannedPortCount = rep.scanned;
                        Progress = (double)rep.scanned / rep.total * 100;

                        if (rep.result != null)
                        {
                            OpenPorts.Add(rep.result);
                            OpenPortCount++;
                            AddLog($"  Port {rep.result.Port}/{rep.result.Protocol} AÇIK — {rep.result.ServiceName}");
                        }
                    });
                });

                List<PortInfo> scanResults;

                if (ScanMethod == ScanType.TCP)
                    scanResults = await ScanTcpAsync(resolvedIp, ports, portProgress, ct);
                else if (ScanMethod == ScanType.SYN)
                    scanResults = await ScanSynAsync(resolvedIp, ports, portProgress, ct);
                else if (ScanMethod == ScanType.UDP)
                    scanResults = await ScanUdpAsync(resolvedIp, ports, portProgress, ct);
                else
                    scanResults = new List<PortInfo>();

                // 7. Banner Grabbing ve SSL Analizi
                var openOnes = scanResults.FindAll(p => p.State == PortState.Open);

                if (EnableBanner && openOnes.Count > 0)
                {
                    AddLog($"{openOnes.Count} açık portta banner grabbing...");
                    await Task.WhenAll(openOnes.Select(async portInfo =>
                    {
                        portInfo.Banner = await _bannerGrabber.GrabAsync(resolvedIp, portInfo.Port, TimeoutMs, ct);
                        portInfo.Version = _bannerGrabber.ParseVersion(portInfo.Banner, portInfo.Port);
                        if (!string.IsNullOrEmpty(portInfo.Version))
                            AddLogSafe($"  Port {portInfo.Port}: {portInfo.Version}");

                        if (EnableSsl && (portInfo.Port == 443 || portInfo.Port == 8443 ||
                            portInfo.Port == 465 || portInfo.Port == 993 || portInfo.Port == 995))
                        {
                            portInfo.SslDetails = await _sslAnalyzer.AnalyzeAsync(resolvedIp, portInfo.Port, TimeoutMs, ct);
                            if (portInfo.SslDetails != null)
                            {
                                portInfo.HasSsl = true;
                                AddLogSafe($"  SSL Port {portInfo.Port}: {portInfo.SslDetails.CommonName} | Exp: {portInfo.SslDetails.ValidTo:yyyy-MM-dd}");
                                Application.Current.Dispatcher.Invoke(() => SslPorts.Add(portInfo));
                            }
                        }
                    }));
                }

                // 8. OS tahminini portlarla zenginleştir
                if (EnableOsDetection && openOnes.Count > 0)
                {
                    osGuess = _osFinger.RefineOsGuess(osGuess, openOnes);
                    CurrentResult.OsGuess = osGuess;
                    AddLog($"OS Tahmini (geliştirilmiş): {osGuess}");
                }

                // 9. Sonuçları kaydet
                scanResults = scanResults
                    .Where(p => p.State == PortState.Open || p.State == PortState.OpenFiltered)
                    .OrderBy(p => p.Port)
                    .ToList();
                CurrentResult.Ports = scanResults;
                CurrentResult.ScanFinished = DateTime.Now;
                AllResults.Add(CurrentResult);
                ScanHistory.Insert(0, CurrentResult);
                SaveHistoryToDisk();

                sw.Stop();
                AddLog($"Tarama tamamlandı! Süre: {sw.Elapsed.TotalSeconds:F1}s | Açık: {openOnes.Count} | Kapalı: {scanResults.Count - openOnes.Count}");
                ScanStats = $"{openOnes.Count} açık / {scanResults.Count} toplam port | {sw.Elapsed.TotalSeconds:F1}s";
            }
            catch (OperationCanceledException)
            {
                AddLog("Tarama iptal edildi.");
            }
            catch (Exception ex)
            {
                AddLog($"Hata: {ex.Message}");
            }
            finally
            {
                IsScanning = false;
                Progress = 100;
            }
        }

        private async Task<List<PortInfo>> ScanTcpAsync(string host, List<int> ports,
            IProgress<(int, int, PortInfo?)> progress, CancellationToken ct)
        {
            var results = new System.Collections.Concurrent.ConcurrentBag<PortInfo>();
            int scanned = 0;
            int total = ports.Count;
            var semaphore = new SemaphoreSlim(ThreadCount);
            var tasks = new List<Task>();

            foreach (int port in ports)
            {
                if (ct.IsCancellationRequested) break;
                int p = port;
                await semaphore.WaitAsync(ct);

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var info = await _tcpScanner.ScanPortAsync(host, p, TimeoutMs, RetryCount, ct);
                        results.Add(info);
                        int s = Interlocked.Increment(ref scanned);
                        progress.Report((s, total, info.State == PortState.Open ? info : null));
                    }
                    finally { semaphore.Release(); }
                }, ct));
            }

            await Task.WhenAll(tasks);
            return new List<PortInfo>(results);
        }

        private async Task<List<PortInfo>> ScanSynAsync(string host, List<int> ports,
            IProgress<(int, int, PortInfo?)> progress, CancellationToken ct)
        {
            var results = new System.Collections.Concurrent.ConcurrentBag<PortInfo>();
            int scanned = 0;
            int total = ports.Count;
            var semaphore = new SemaphoreSlim(ThreadCount);
            var tasks = new List<Task>();

            foreach (int port in ports)
            {
                if (ct.IsCancellationRequested) break;
                int p = port;
                await semaphore.WaitAsync(ct);

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var info = await _synScanner.ScanPortAsync(host, p, TimeoutMs, ct);
                        results.Add(info);
                        int s = Interlocked.Increment(ref scanned);
                        progress.Report((s, total, info.State == PortState.Open ? info : null));
                    }
                    finally { semaphore.Release(); }
                }, ct));
            }

            await Task.WhenAll(tasks);
            return new List<PortInfo>(results);
        }

        private async Task<List<PortInfo>> ScanUdpAsync(string host, List<int> ports,
            IProgress<(int, int, PortInfo?)> progress, CancellationToken ct)
        {
            var results = new System.Collections.Concurrent.ConcurrentBag<PortInfo>();
            int scanned = 0;
            int total = ports.Count;
            var semaphore = new SemaphoreSlim(Math.Min(ThreadCount, 50));
            var tasks = new List<Task>();

            foreach (int port in ports)
            {
                if (ct.IsCancellationRequested) break;
                int p = port;
                await semaphore.WaitAsync(ct);

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var info = await _udpScanner.ScanPortAsync(host, p, TimeoutMs, ct);
                        results.Add(info);
                        int s = Interlocked.Increment(ref scanned);
                        progress.Report((s, total, info.State != PortState.Closed ? info : null));
                    }
                    finally { semaphore.Release(); }
                }, ct));
            }

            await Task.WhenAll(tasks);
            return new List<PortInfo>(results);
        }

        public void StopScan() => _cts?.Cancel();

        // Port Parsing
        private List<int> GetPortList()
        {
            var ports = new HashSet<int>();

            if (!string.IsNullOrWhiteSpace(CustomPorts))
            {
                foreach (var part in CustomPorts.Split(','))
                {
                    var t = part.Trim();
                    if (t.Contains('-'))
                    {
                        var bounds = t.Split('-');
                        if (int.TryParse(bounds[0], out int s) && int.TryParse(bounds[1], out int e))
                            for (int i = s; i <= e; i++) ports.Add(i);
                    }
                    else if (int.TryParse(t, out int p)) ports.Add(p);
                }
            }
            else if (!string.IsNullOrWhiteSpace(PortRange))
            {
                var parts = PortRange.Split('-');
                if (parts.Length == 2 && int.TryParse(parts[0], out int s) && int.TryParse(parts[1], out int e))
                    for (int i = s; i <= e; i++) ports.Add(i);
            }

            return new List<int>(ports);
        }

        // DNS Resolve
        private async Task<string> ResolveHostAsync(string host)
        {
            if (IPAddress.TryParse(host, out _)) return host;
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(host);
                return addresses.Length > 0 ? addresses[0].ToString() : host;
            }
            catch { return host; }
        }

        // Profiles
        private void LoadDefaultProfiles()
        {
            LoadProfilesFromDisk();

            if (SavedProfiles.Count == 0)
            {
                foreach (var p in ScanProfile.DefaultProfiles)
                    SavedProfiles.Add(p);
                SaveProfilesToDisk();
            }
        }

        public void ApplyProfile(ScanProfile profile)
        {
            TargetHost = profile.TargetHost.Length > 0 ? profile.TargetHost : TargetHost;
            PortRange = profile.PortRange;
            CustomPorts = profile.CustomPorts;
            ScanMethod = profile.ScanMethod;
            TimeoutMs = profile.TimeoutMs;
            RetryCount = profile.RetryCount;
            ThreadCount = profile.ThreadCount;
            EnableBanner = profile.EnableBannerGrab;
            EnableOsDetection = profile.EnableOsDetection;
            EnableSsl = profile.EnableSslAnalysis;
            EnableWhois = profile.EnableWhois;
            AddLog($"Profil yüklendi: {profile.Name}");
        }

        public void SaveCurrentProfile(string name)
        {
            var profile = new ScanProfile
            {
                Name = name,
                TargetHost = TargetHost,
                PortRange = PortRange,
                CustomPorts = CustomPorts,
                ScanMethod = ScanMethod,
                TimeoutMs = TimeoutMs,
                RetryCount = RetryCount,
                ThreadCount = ThreadCount,
                EnableBannerGrab = EnableBanner,
                EnableOsDetection = EnableOsDetection,
                EnableSslAnalysis = EnableSsl,
                EnableWhois = EnableWhois
            };

            SavedProfiles.Add(profile);
            SaveProfilesToDisk();
            AddLog($"Profil kaydedildi: {name}");
        }

        public void DeleteProfile(ScanProfile profile)
        {
            SavedProfiles.Remove(profile);
            SaveProfilesToDisk();
            AddLog($"Profil silindi: {profile.Name}");
        }

        public void DeleteHistory(ScanResult result)
        {
            ScanHistory.Remove(result);
            SaveHistoryToDisk();
            AddLog($"Geçmiş silindi: {result.TargetHost}");
        }

        public void ClearAllHistory()
        {
            ScanHistory.Clear();
            SaveHistoryToDisk();
            AddLog("Tüm geçmiş temizlendi.");
        }

        // Paths
        private string ProfilePath => System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PortScope", "profiles.json");

        private string HistoryPath => System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PortScope", "history.json");

        // Disk I/O
        private void SaveProfilesToDisk()
        {
            try
            {
                System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(ProfilePath)!);
                var json = JsonSerializer.Serialize(SavedProfiles.ToList(), new JsonSerializerOptions { WriteIndented = true });
                System.IO.File.WriteAllText(ProfilePath, json);
            }
            catch { }
        }

        private void SaveHistoryToDisk()
        {
            try
            {
                System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(HistoryPath)!);
                var json = JsonSerializer.Serialize(ScanHistory.ToList(), new JsonSerializerOptions { WriteIndented = true });
                System.IO.File.WriteAllText(HistoryPath, json);
            }
            catch { }
        }

        private void LoadProfilesFromDisk()
        {
            try
            {
                if (!System.IO.File.Exists(ProfilePath)) return;
                var json = System.IO.File.ReadAllText(ProfilePath);
                var profiles = JsonSerializer.Deserialize<List<ScanProfile>>(json);
                if (profiles == null) return;
                foreach (var p in profiles)
                    SavedProfiles.Add(p);
            }
            catch { }
        }

        private void LoadHistoryFromDisk()
        {
            try
            {
                if (!System.IO.File.Exists(HistoryPath)) return;
                var json = System.IO.File.ReadAllText(HistoryPath);
                var list = JsonSerializer.Deserialize<List<ScanResult>>(json);
                if (list == null) return;
                foreach (var item in list)
                    ScanHistory.Add(item);
            }
            catch { }
        }

        // Export
        public void ExportResults(string path, string format)
        {
            try
            {
                if (AllResults.Count == 0) { AddLog("Dışa aktarılacak sonuç yok"); return; }

                switch (format.ToLower())
                {
                    case "json": _exporter.ExportJson(AllResults, path); break;
                    case "csv": _exporter.ExportCsv(AllResults, path); break;
                    case "xml": _exporter.ExportXml(AllResults, path); break;
                    case "html": _exporter.ExportHtml(AllResults, path); break;
                }
                AddLog($"Rapor kaydedildi: {path}");
            }
            catch (Exception ex)
            {
                AddLog($"Export hatası: {ex.Message}");
            }
        }

        // Helpers
        private void AddLog(string msg) =>
            Application.Current.Dispatcher.Invoke(() =>
            {
                Logs.Insert(0, $"[{DateTime.Now:HH:mm:ss}] {msg}");
                if (Logs.Count > 500) Logs.RemoveAt(Logs.Count - 1);
            });

        private void AddLogSafe(string msg) =>
            Application.Current.Dispatcher.Invoke(() =>
                Logs.Insert(0, $"[{DateTime.Now:HH:mm:ss}] {msg}"));

        // INotifyPropertyChanged
        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        private bool Set<T>(ref T field, T val, [CallerMemberName] string? name = null)
        {
            if (Equals(field, val)) return false;
            field = val; OnPropertyChanged(name); return true;
        }
    }
}