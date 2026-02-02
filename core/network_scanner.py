"""
Moduł skanowania sieci lokalnej za pomocą nmap
"""
import nmap
import subprocess
import re
from datetime import datetime
from app import db
from app.models import Device, Alert
from core.email_manager import EmailManager
from config import Config


class NetworkScanner:
    """Skaner sieci lokalnej wykorzystujący nmap"""
    
    def __init__(self, network_range='192.168.1.0/24', email_manager=None):
        """
        Inicjalizacja skanera
        
        Args:
            network_range: Zakres sieci do skanowania (CIDR notation)
            email_manager: Instancja EmailManager do wysyłania powiadomień
        """
        self.network_range = network_range
        self.nm = nmap.PortScanner()
        self.email_manager = email_manager or EmailManager(Config)
    
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
    