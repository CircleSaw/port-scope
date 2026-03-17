using System.Collections.Generic;

namespace PortScope.Services
{
    public static class WellKnownPorts
    {
        private static readonly Dictionary<int, string> Services = new()
        {
            {20,"FTP-Data"},{21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},
            {53,"DNS"},{67,"DHCP"},{68,"DHCP"},{69,"TFTP"},{80,"HTTP"},
            {88,"Kerberos"},{110,"POP3"},{111,"RPCbind"},{119,"NNTP"},
            {123,"NTP"},{135,"MSRPC"},{137,"NetBIOS-NS"},{138,"NetBIOS-DGM"},
            {139,"NetBIOS-SSN"},{143,"IMAP"},{161,"SNMP"},{162,"SNMPTRAP"},
            {179,"BGP"},{194,"IRC"},{389,"LDAP"},{443,"HTTPS"},{445,"SMB"},
            {465,"SMTPS"},{500,"IKE"},{514,"Syslog"},{515,"LPD"},{587,"SMTP"},
            {631,"IPP"},{636,"LDAPS"},{993,"IMAPS"},{995,"POP3S"},
            {1080,"SOCKS"},{1194,"OpenVPN"},{1433,"MSSQL"},{1521,"Oracle"},
            {1723,"PPTP"},{2049,"NFS"},{2181,"Zookeeper"},{3306,"MySQL"},
            {3389,"RDP"},{4444,"Metasploit"},{5432,"PostgreSQL"},{5900,"VNC"},
            {5985,"WinRM"},{6379,"Redis"},{6443,"Kubernetes"},{8080,"HTTP-Alt"},
            {8443,"HTTPS-Alt"},{8888,"Jupyter"},{9200,"Elasticsearch"},
            {27017,"MongoDB"},{27018,"MongoDB"},{50070,"Hadoop"}
        };

        public static string GetServiceName(int port) =>
            Services.TryGetValue(port, out var name) ? name : "unknown";
    }
}