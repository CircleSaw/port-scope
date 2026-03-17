# PortScope

C# ve WPF tabanlı Windows port tarama aracı.

## Ne Yapar

Hedef bir IP veya domain üzerindeki açık portları tarar. Açık portlarda hangi servisin çalıştığını, versiyonunu ve SSL sertifika bilgilerini gösterir.

## Özellikler

- TCP, SYN ve UDP tarama
- Banner grabbing, servis ve versiyon tespiti
- SSL/TLS sertifika analizi
- TTL bazlı OS tahmini
- WHOIS ve DNS sorgulama
- Tarama profili kaydetme
- Geçmiş taramaları saklama
- JSON, CSV, XML, HTML export

## Kurulum

```
git clone https://github.com/CircleSaw/port-scope.git
```

Visual Studio 2022+ ile aç, NuGet'ten `Newtonsoft.Json` yükle, build al.

SYN tarama kullanacaksan yönetici olarak çalıştır.

## Kullanım

Target alanına IP ya da domain yaz, port aralığını ve tarama yöntemini seç, START SCAN'e bas. Sonuçlar Open Ports sekmesine düşer, WHOIS ve SSL bilgileri kendi sekmelerinde görünür.

## Stack

- C# / .NET 8
- WPF, MVVM
- async/await
