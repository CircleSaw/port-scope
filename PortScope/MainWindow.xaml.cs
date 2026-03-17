using System;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using PortScope.Models;
using PortScope.ViewModels;

namespace PortScope
{
    public partial class MainWindow : Window
    {
        private readonly MainViewModel _vm;
        private readonly DispatcherTimer _clockTimer;

        public MainWindow()
        {
            InitializeComponent();
            _vm = new MainViewModel();
            DataContext = _vm;

            _clockTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _clockTimer.Tick += (s, e) => TxtClock.Text = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            _clockTimer.Start();
        }

        private async void BtnStartScan_Click(object sender, RoutedEventArgs e)
        {
            await _vm.StartScanAsync();
        }

        private void BtnStopScan_Click(object sender, RoutedEventArgs e)
        {
            _vm.StopScan();
        }

        private void BtnClearLog_Click(object sender, RoutedEventArgs e)
        {
            _vm.Logs.Clear();
        }

        private void LstProfiles_SelectionChanged(object sender, SelectionChangedEventArgs e) { }

        private void BtnLoadProfile_Click(object sender, RoutedEventArgs e)
        {
            if (lstProfiles.SelectedItem is ScanProfile profile)
                _vm.ApplyProfile(profile);
            else
                MessageBox.Show("Bir profil seçin.", "PortScope", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void BtnSaveProfile_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveProfileDialog();
            if (dialog.ShowDialog() == true && !string.IsNullOrWhiteSpace(dialog.ProfileName))
                _vm.SaveCurrentProfile(dialog.ProfileName);
        }

        private void BtnDeleteProfile_Click(object sender, RoutedEventArgs e)
        {
            if (lstProfiles.SelectedItem is ScanProfile profile)
            {
                var result = MessageBox.Show($"'{profile.Name}' profilini silmek istediğine emin misin?",
                    "Profil Sil", MessageBoxButton.YesNo, MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                    _vm.DeleteProfile(profile);
            }
            else
            {
                MessageBox.Show("Silmek için bir profil seçin.", "PortScope",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void BtnExportJson_Click(object sender, RoutedEventArgs e) => Export("json", "JSON Files|*.json");
        private void BtnExportCsv_Click(object sender, RoutedEventArgs e) => Export("csv", "CSV Files|*.csv");
        private void BtnExportXml_Click(object sender, RoutedEventArgs e) => Export("xml", "XML Files|*.xml");
        private void BtnExportHtml_Click(object sender, RoutedEventArgs e) => Export("html", "HTML Files|*.html");

        private void Export(string format, string filter)
        {
            var dlg = new SaveFileDialog
            {
                Filter = filter,
                FileName = $"portscope_{_vm.TargetHost}_{DateTime.Now:yyyyMMdd_HHmmss}"
            };
            if (dlg.ShowDialog() == true)
                _vm.ExportResults(dlg.FileName, format);
        }

        private async void BtnDnsLookup_Click(object sender, RoutedEventArgs e)
        {
            string host = TxtDnsLookup.Text.Trim();
            if (string.IsNullOrEmpty(host)) return;

            TxtDnsResult.Text = "Resolving...";
            try
            {
                var entry = await Dns.GetHostEntryAsync(host);
                string result = $"Hostname: {entry.HostName}\n";
                result += "IPs:\n";
                foreach (var ip in entry.AddressList)
                    result += $"  {ip}\n";
                if (entry.Aliases.Length > 0)
                {
                    result += "Aliases:\n";
                    foreach (var alias in entry.Aliases)
                        result += $"  {alias}\n";
                }
                TxtDnsResult.Text = result;
            }
            catch (Exception ex)
            {
                TxtDnsResult.Text = $"Error: {ex.Message}";
            }
        }

        private void DgPorts_SelectionChanged(object sender, SelectionChangedEventArgs e) { }

        private void BtnDeleteHistory_Click(object sender, RoutedEventArgs e)
        {
            if (DgHistory.SelectedItem is ScanResult result)
            {
                var res = MessageBox.Show($"'{result.TargetHost}' geçmişini silmek istediğine emin misin?",
                    "Geçmiş Sil", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (res == MessageBoxResult.Yes)
                    _vm.DeleteHistory(result);
            }
            else
            {
                MessageBox.Show("Silmek için bir kayıt seçin.", "PortScope",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void BtnClearHistory_Click(object sender, RoutedEventArgs e)
        {
            var res = MessageBox.Show("Tüm geçmişi silmek istediğine emin misin?",
                "Geçmişi Temizle", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (res == MessageBoxResult.Yes)
                _vm.ClearAllHistory();
        }
    }

    public class SaveProfileDialog : Window
    {
        public string ProfileName { get; private set; } = "";

        public SaveProfileDialog()
        {
            Title = "Save Profile";
            Width = 340;
            Height = 170;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Background = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(0x16, 0x1b, 0x22));
            ResizeMode = ResizeMode.NoResize;

            var panel = new System.Windows.Controls.StackPanel { Margin = new Thickness(16) };

            var lbl = new System.Windows.Controls.TextBlock
            {
                Text = "Profile Name:",
                Foreground = System.Windows.Media.Brushes.LightGray,
                Margin = new Thickness(0, 0, 0, 6)
            };

            var txt = new System.Windows.Controls.TextBox
            {
                Background = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x21, 0x26, 0x2d)),
                Foreground = System.Windows.Media.Brushes.White,
                BorderBrush = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x30, 0x36, 0x3d)),
                Padding = new Thickness(8, 6, 8, 6),
                Margin = new Thickness(0, 0, 0, 12)
            };

            var btnPanel = new System.Windows.Controls.StackPanel
            {
                Orientation = System.Windows.Controls.Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right
            };

            var btnSave = new System.Windows.Controls.Button
            {
                Content = "Save",
                Padding = new Thickness(16, 6, 16, 6),
                Margin = new Thickness(0, 0, 8, 0),
                Background = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x23, 0x86, 0x36)),
                Foreground = System.Windows.Media.Brushes.White,
                BorderThickness = new Thickness(0),
                Cursor = System.Windows.Input.Cursors.Hand
            };

            var btnCancel = new System.Windows.Controls.Button
            {
                Content = "Cancel",
                Padding = new Thickness(16, 6, 16, 6),
                Background = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x21, 0x26, 0x2d)),
                Foreground = System.Windows.Media.Brushes.White,
                BorderThickness = new Thickness(0),
                Cursor = System.Windows.Input.Cursors.Hand
            };

            btnSave.Click += (s, e) => { ProfileName = txt.Text; DialogResult = true; };
            btnCancel.Click += (s, e) => { DialogResult = false; };

            btnPanel.Children.Add(btnSave);
            btnPanel.Children.Add(btnCancel);
            panel.Children.Add(lbl);
            panel.Children.Add(txt);
            panel.Children.Add(btnPanel);
            Content = panel;
        }
    }
}