using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Xml.Serialization;
using PortScope.Models;

namespace PortScope.Services
{
    public class ReportExporter
    {
        public void ExportJson(List<ScanResult> results, string filePath)
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            var json = JsonSerializer.Serialize(results, options);
            File.WriteAllText(filePath, json, Encoding.UTF8);
        }

        public void ExportCsv(List<ScanResult> results, string filePath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Host,IP,Port,Protocol,State,Service,Version,Banner,HasSSL,SSL_CN,SSL_Expiry,ResponseMs,ScannedAt");

            foreach (var result in results)
            {
                foreach (var port in result.Ports)
                {
                    sb.AppendLine(string.Join(",",
                        Escape(result.TargetHost),
                        Escape(result.ResolvedIp),
                        port.Port,
                        port.Protocol,
                        port.State,
                        Escape(port.ServiceName),
                        Escape(port.Version),
                        Escape(port.Banner?.Replace("\n", " ") ?? ""),
                        port.HasSsl,
                        Escape(port.SslDetails?.CommonName ?? ""),
                        port.SslDetails?.ValidTo.ToString("yyyy-MM-dd") ?? "",
                        port.ResponseTimeMs,
                        port.ScannedAt.ToString("yyyy-MM-dd HH:mm:ss")
                    ));
                }
            }

            File.WriteAllText(filePath, sb.ToString(), Encoding.UTF8);
        }

        public void ExportXml(List<ScanResult> results, string filePath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            sb.AppendLine("<PortScopeReport generated=\"" + DateTime.Now.ToString("o") + "\">");

            foreach (var result in results)
            {
                sb.AppendLine($"  <Host address=\"{Xml(result.TargetHost)}\" ip=\"{Xml(result.ResolvedIp)}\" os=\"{Xml(result.OsGuess)}\" alive=\"{result.IsAlive}\">");
                sb.AppendLine($"    <ScanInfo method=\"{result.ScanMethod}\" duration=\"{result.Duration.TotalSeconds:F2}s\" openPorts=\"{result.OpenPortCount}\"/>");

                if (result.WhoisData != null)
                {
                    var w = result.WhoisData;
                    sb.AppendLine($"    <Whois org=\"{Xml(w.Organization)}\" country=\"{Xml(w.Country)}\" registrar=\"{Xml(w.Registrar)}\"/>");
                }

                sb.AppendLine("    <Ports>");
                foreach (var port in result.Ports)
                {
                    if (port.State == PortState.Open || port.State == PortState.OpenFiltered)
                    {
                        sb.AppendLine($"      <Port number=\"{port.Port}\" protocol=\"{port.Protocol}\" state=\"{port.State}\" service=\"{Xml(port.ServiceName)}\" version=\"{Xml(port.Version)}\" ssl=\"{port.HasSsl}\" responseMs=\"{port.ResponseTimeMs}\"/>");
                    }
                }
                sb.AppendLine("    </Ports>");
                sb.AppendLine("  </Host>");
            }

            sb.AppendLine("</PortScopeReport>");
            File.WriteAllText(filePath, sb.ToString(), Encoding.UTF8);
        }

        public void ExportHtml(List<ScanResult> results, string filePath)
        {
            var sb = new StringBuilder();
            sb.AppendLine(@"<!DOCTYPE html>
<html>
<head>
<meta charset='UTF-8'>
<title>PortScope Report</title>
<style>
body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px}
h1{color:#58a6ff}h2{color:#3fb950}
table{border-collapse:collapse;width:100%;margin-bottom:20px}
th{background:#161b22;color:#58a6ff;padding:8px;border:1px solid #30363d}
td{padding:6px 8px;border:1px solid #21262d}
.open{color:#3fb950}.closed{color:#f85149}.filtered{color:#d29922}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px}
.badge-ssl{background:#1f6feb;color:white}
</style>
</head>
<body>
<h1>PortScope Report</h1>
<p>Generated: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + @"</p>");

            foreach (var result in results)
            {
                sb.AppendLine($"<h2>{result.TargetHost} ({result.ResolvedIp})</h2>");
                sb.AppendLine($"<p>OS: {result.OsGuess} | Scan: {result.ScanMethod} | Duration: {result.Duration.TotalSeconds:F2}s | Open: {result.OpenPortCount}</p>");

                sb.AppendLine("<table><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version</th><th>SSL</th><th>Response</th></tr>");
                foreach (var port in result.Ports)
                {
                    string cls = port.State == PortState.Open ? "open" : port.State == PortState.Closed ? "closed" : "filtered";
                    string ssl = port.HasSsl ? "<span class='badge badge-ssl'>SSL</span>" : "";
                    sb.AppendLine($"<tr><td>{port.Port}</td><td>{port.Protocol}</td><td class='{cls}'>{port.State}</td><td>{port.ServiceName}</td><td>{port.Version}</td><td>{ssl}</td><td>{port.ResponseTimeMs}ms</td></tr>");
                }
                sb.AppendLine("</table>");
            }

            sb.AppendLine("</body></html>");
            File.WriteAllText(filePath, sb.ToString(), Encoding.UTF8);
        }

        private string Escape(string? s) => $"\"{(s ?? "").Replace("\"", "\"\"")}\"";
        private string Xml(string? s) => System.Security.SecurityElement.Escape(s ?? "") ?? "";
    }
}