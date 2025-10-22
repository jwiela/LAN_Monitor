"""
Moduł skanowania sieci lokalnej za pomocą nmap
"""
import nmap
import subprocess
import re
from datetime import datetime
from app import db
from app.models import Device, Alert


class NetworkScanner:
    """Skaner sieci lokalnej wykorzystujący nmap"""
    
    def __init__(self, network_range='192.168.1.0/24'):
        """
        Inicjalizacja skanera
        
        Args:
            network_range: Zakres sieci do skanowania (CIDR notation)
        """
        self.network_range = network_range
        self.nm = nmap.PortScanner()
    
    def scan_network(self):
        """
        Skanuje sieć w poszukiwaniu aktywnych urządzeń
        
        Returns:
            dict: Słownik z informacjami o znalezionych urządzeniach
        """
        print(f"🔍 Rozpoczynam skanowanie sieci: {self.network_range}")
        
        try:
            # Skanowanie ping (szybkie wykrywanie hostów)
            # -sn: Ping scan (bez skanowania portów)
            # -PE: ICMP echo request
            # --privileged: Używa uprawnień root dla lepszego wykrywania MAC
            self.nm.scan(hosts=self.network_range, arguments='-sn -PE --privileged')
            
            devices = {}
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    device_info = self._get_device_info(host)
                    if device_info:
                        devices[host] = device_info
                        mac_display = device_info.get('mac', 'Brak MAC')
                        print(f"  ✓ Znaleziono: {host} ({mac_display})")
            
            print(f"✅ Skanowanie zakończone. Znaleziono {len(devices)} urządzeń.")
            return devices
            
        except Exception as e:
            print(f"❌ Błąd podczas skanowania: {e}")
            return {}
    
    def _get_device_info(self, host):
        """
        Pobiera szczegółowe informacje o urządzeniu
        
        Args:
            host: Adres IP hosta
            
        Returns:
            dict: Informacje o urządzeniu (IP, MAC, vendor, hostname)
        """
        device_info = {
            'ip': host,
            'mac': None,
            'vendor': None,
            'hostname': None
        }
        
        # Pobierz adres MAC i vendor
        if 'addresses' in self.nm[host]:
            if 'mac' in self.nm[host]['addresses']:
                device_info['mac'] = self.nm[host]['addresses']['mac']
        
        # Pobierz vendor z nmap
        if 'vendor' in self.nm[host] and device_info['mac']:
            vendor_dict = self.nm[host]['vendor']
            if device_info['mac'] in vendor_dict:
                device_info['vendor'] = vendor_dict[device_info['mac']]
        
        # Pobierz hostname
        if 'hostnames' in self.nm[host]:
            hostnames = self.nm[host]['hostnames']
            if hostnames and len(hostnames) > 0:
                device_info['hostname'] = hostnames[0].get('name', None)
        
        # Jeśli nie ma hostname, spróbuj reverse DNS
        if not device_info['hostname']:
            device_info['hostname'] = self._get_hostname(host)
        
        return device_info
    
    def _get_hostname(self, ip):
        """
        Próbuje uzyskać hostname przez reverse DNS
        
        Args:
            ip: Adres IP
            
        Returns:
            str: Hostname lub None
        """
        try:
            result = subprocess.run(
                ['host', ip],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode == 0:
                # Parsuj wynik: "x.x.x.x.in-addr.arpa domain name pointer hostname."
                match = re.search(r'pointer (.+)\.$', result.stdout)
                if match:
                    return match.group(1)
        except Exception:
            pass
        
        return None
    
    def update_database(self, devices):
        """
        Aktualizuje bazę danych na podstawie wyników skanowania
        
        Args:
            devices: Słownik urządzeń ze skanowania
        """
        print("💾 Aktualizuję bazę danych...")
        
        # Oznacz wszystkie urządzenia jako offline na początek
        Device.query.update({'is_online': False})
        
        devices_added = 0
        devices_updated = 0
        
        for ip, info in devices.items():
            mac = info.get('mac')
            
            # Jeśli brak MAC, użyj IP jako tymczasowego identyfikatora
            if not mac:
                print(f"  ⚠ Urządzenie {ip} bez adresu MAC - używam IP jako identyfikatora")
                # Szukaj po IP dla urządzeń bez MAC
                device = Device.query.filter_by(ip_address=ip, mac_address=None).first()
            else:
                # Znajdź urządzenie po MAC (najlepszy identyfikator)
                device = Device.query.filter_by(mac_address=mac).first()
            
            if device:
                # Urządzenie istnieje - aktualizuj
                device.ip_address = ip
                if mac:  # Aktualizuj MAC jeśli teraz został wykryty
                    device.mac_address = mac
                device.hostname = info.get('hostname')
                device.vendor = info.get('vendor')
                device.is_online = True
                device.is_new = False  # Nie jest już nowe
                device.update_last_seen()
                devices_updated += 1
                print(f"  ↻ Zaktualizowano: {mac or ip} ({ip})")
            else:
                # Nowe urządzenie - dodaj
                device = Device(
                    mac_address=mac,  # Może być None
                    ip_address=ip,
                    hostname=info.get('hostname'),
                    vendor=info.get('vendor'),
                    is_online=True,
                    is_new=True
                )
                db.session.add(device)
                devices_added += 1
                print(f"  + Dodano nowe urządzenie: {mac or 'brak MAC'} ({ip})")
                
                # Utwórz alert o nowym urządzeniu
                device_identifier = mac if mac else ip
                alert = Alert(
                    alert_type='new_device',
                    severity='info',
                    message=f'Wykryto nowe urządzenie w sieci: {device_identifier} ({ip})',
                    device=device
                )
                db.session.add(alert)
        
        try:
            db.session.commit()
            print(f"✅ Baza danych zaktualizowana: +{devices_added} nowych, ↻{devices_updated} zaktualizowanych")
        except Exception as e:
            db.session.rollback()
            print(f"❌ Błąd podczas zapisu do bazy: {e}")
    
    def get_network_interface_range(self):
        """
        Automatycznie wykrywa zakres sieci na podstawie interfejsu sieciowego
        
        Returns:
            str: Zakres sieci w notacji CIDR
        """
        try:
            result = subprocess.run(
                ['ip', 'route', 'show'],
                capture_output=True,
                text=True
            )
            
            # Szukaj linii z domyślną trasą lokalną
            for line in result.stdout.split('\n'):
                if 'scope link' in line or 'proto kernel' in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', line)
                    if match:
                        return match.group(1)
        except Exception:
            pass
        
        # Domyślny zakres jeśli nie udało się wykryć
        return '192.168.1.0/24'


def run_scan():
    """
    Funkcja pomocnicza do uruchomienia skanowania
    (może być wywołana z crona lub schedulera)
    """
    scanner = NetworkScanner()
    
    # Automatyczne wykrycie zakresu sieci
    network_range = scanner.get_network_interface_range()
    scanner.network_range = network_range
    
    # Wykonaj skanowanie
    devices = scanner.scan_network()
    
    # Aktualizuj bazę danych
    if devices:
        scanner.update_database(devices)
    
    return len(devices)
