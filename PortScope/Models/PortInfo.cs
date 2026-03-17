using System;
using System.ComponentModel;
using PortScope.Models;

namespace PortScope.Models
{
    public enum PortState { Open, Closed, Filtered, OpenFiltered }
    public enum ScanType { TCP, SYN, UDP, ICMP }

    public class PortInfo : INotifyPropertyChanged
    {
        public int Port { get; set; }
        public PortState State { get; set; }
        public string Protocol { get; set; } = "TCP";
        public string ServiceName { get; set; } = "";

        private string _banner = "";
        public string Banner
        {
            get => _banner;
            set { _banner = value; OnPropertyChanged(); }
        }

        private string _version = "";
        public string Version
        {
            get => _version;
            set { _version = value; OnPropertyChanged(); }
        }

        private bool _hasSsl;
        public bool HasSsl
        {
            get => _hasSsl;
            set { _hasSsl = value; OnPropertyChanged(); }
        }

        private SslInfo? _sslDetails;
        public SslInfo? SslDetails
        {
            get => _sslDetails;
            set { _sslDetails = value; OnPropertyChanged(); }
        }

        public DateTime ScannedAt { get; set; } = DateTime.Now;
        public long ResponseTimeMs { get; set; }

        public string StateDisplay => State switch
        {
            PortState.Open => "OPEN",
            PortState.Closed => "CLOSED",
            PortState.Filtered => "FILTERED",
            PortState.OpenFiltered => "OPEN|FILTERED",
            _ => "UNKNOWN"
        };

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}