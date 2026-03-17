using System;

namespace PortScope.Models
{
    public class SslInfo
    {
        public string CommonName { get; set; } = "";
        public string Issuer { get; set; } = "";
        public DateTime ValidFrom { get; set; }
        public DateTime ValidTo { get; set; }
        public string SignatureAlgorithm { get; set; } = "";
        public string[] SubjectAltNames { get; set; } = Array.Empty<string>();
        public bool IsExpired => DateTime.Now > ValidTo;
        public int DaysUntilExpiry => (ValidTo - DateTime.Now).Days;
    }
}