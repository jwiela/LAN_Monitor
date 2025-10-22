#!/usr/bin/env python3
"""
Moduł monitorowania ruchu sieciowego
Przechwytuje pakiety z interfejsu mirror i agreguje statystyki dla każdego urządzenia
"""
import logging
import threading
import time
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP
from typing import Dict, Tuple

logger = logging.getLogger(__name__)


class TrafficMonitor:
    """Monitor ruchu sieciowego używający Scapy do przechwytywania pakietów"""
    
    def __init__(self, interface='eth0', update_interval=60):
        """
        Args:
            interface: Interfejs sieciowy do nasłuchiwania (port mirror)
            update_interval: Interwał zapisu danych do bazy (sekundy)
        """
        self.interface = interface
        self.update_interval = update_interval
        self.running = False
        self.thread = None
        
        # Statystyki: {ip_address: {'bytes_in': int, 'bytes_out': int, 'packets_in': int, 'packets_out': int, 'last_update': float}}
        self.stats = defaultdict(lambda: {'bytes_in': 0, 'bytes_out': 0, 'packets_in': 0, 'packets_out': 0, 'last_update': time.time()})
        self.stats_lock = threading.Lock()
        
        # IP sieci lokalnej (do określenia kierunku ruchu)
        self.local_network = '192.168.1.0/24'
        self.local_ips = set()
        
    def _is_local_ip(self, ip: str) -> bool:
        """Sprawdza czy IP należy do sieci lokalnej"""
        try:
            # Proste sprawdzenie dla /24
            parts = ip.split('.')
            local_parts = self.local_network.split('/')[0].split('.')
            return parts[0] == local_parts[0] and parts[1] == local_parts[1] and parts[2] == local_parts[2]
        except:
            return False
    
    def _packet_handler(self, packet):
        """Callback dla każdego przechwyconego pakietu"""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_size = len(packet)
                
                src_local = self._is_local_ip(src_ip)
                dst_local = self._is_local_ip(dst_ip)
                
                with self.stats_lock:
                    # Ruch wychodzący (z sieci lokalnej)
                    if src_local and not dst_local:
                        self.stats[src_ip]['bytes_out'] += packet_size
                        self.stats[src_ip]['packets_out'] += 1
                    
                    # Ruch przychodzący (do sieci lokalnej)
                    elif not src_local and dst_local:
                        self.stats[dst_ip]['bytes_in'] += packet_size
                        self.stats[dst_ip]['packets_in'] += 1
                    
                    # Ruch wewnętrzny (między urządzeniami lokalnymi)
                    elif src_local and dst_local:
                        self.stats[src_ip]['bytes_out'] += packet_size
                        self.stats[src_ip]['packets_out'] += 1
                        self.stats[dst_ip]['bytes_in'] += packet_size
                        self.stats[dst_ip]['packets_in'] += 1
                        
        except Exception as e:
            logger.error(f"Błąd przetwarzania pakietu: {e}")
    
    def get_stats(self, reset=True) -> Dict[str, Dict[str, int]]:
        """
        Pobiera zgromadzone statystyki
        
        Args:
            reset: Czy wyzerować statystyki po pobraniu
            
        Returns:
            Słownik ze statystykami dla każdego IP
        """
        current_time = time.time()
        with self.stats_lock:
            stats_copy = {}
            for ip, stats in self.stats.items():
                stats_copy[ip] = dict(stats)
            
            if reset:
                # Resetuj liczniki ale zachowaj timestamp
                for ip in self.stats:
                    self.stats[ip]['bytes_in'] = 0
                    self.stats[ip]['bytes_out'] = 0
                    self.stats[ip]['packets_in'] = 0
                    self.stats[ip]['packets_out'] = 0
                    self.stats[ip]['last_update'] = current_time
            
            return stats_copy
    
    def _capture_loop(self):
        """Pętla przechwytywania pakietów"""
        logger.info(f"🎯 Rozpoczynam przechwytywanie pakietów na interfejsie {self.interface}")
        try:
            # Uruchom sniffing w trybie nieograniczonym (count=0)
            # prn=callback, store=0 (nie przechowuj pakietów w pamięci)
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            logger.error("❌ Brak uprawnień do przechwytywania pakietów! Uruchom z sudo.")
        except Exception as e:
            logger.error(f"❌ Błąd podczas przechwytywania: {e}")
        finally:
            logger.info("🛑 Zatrzymano przechwytywanie pakietów")
    
    def start(self):
        """Uruchamia monitoring w osobnym wątku"""
        if self.running:
            logger.warning("Monitor już działa!")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()
        logger.info(f"✅ Traffic monitor uruchomiony na {self.interface}")
    
    def stop(self):
        """Zatrzymuje monitoring"""
        if not self.running:
            return
        
        logger.info("🛑 Zatrzymuję traffic monitor...")
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("✅ Traffic monitor zatrzymany")
    
    def get_current_rates(self) -> Dict[str, Tuple[float, float]]:
        """
        Zwraca aktualne prędkości dla każdego urządzenia (KB/s)
        Oblicza rzeczywistą prędkość na podstawie czasu od ostatniej aktualizacji
        
        Returns:
            {ip: (download_kbps, upload_kbps)}
        """
        current_time = time.time()
        with self.stats_lock:
            rates = {}
            for ip, stats in self.stats.items():
                # Oblicz czas od ostatniej aktualizacji
                time_elapsed = current_time - stats.get('last_update', current_time)
                
                if time_elapsed > 0:
                    # Przelicz na KB/s na podstawie rzeczywistego czasu
                    download_kbps = (stats['bytes_in'] / 1024) / time_elapsed
                    upload_kbps = (stats['bytes_out'] / 1024) / time_elapsed
                else:
                    download_kbps = 0
                    upload_kbps = 0
                
                rates[ip] = (download_kbps, upload_kbps)
            return rates


if __name__ == '__main__':
    # Test modułu
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    monitor = TrafficMonitor(interface='eth0', update_interval=10)
    monitor.start()
    
    try:
        while True:
            time.sleep(10)
            stats = monitor.get_stats(reset=False)
            print("\n=== Statystyki ruchu ===")
            for ip, data in stats.items():
                print(f"{ip}: ↓ {data['bytes_in']/1024:.2f} KB ({data['packets_in']} pkt) | "
                      f"↑ {data['bytes_out']/1024:.2f} KB ({data['packets_out']} pkt)")
    except KeyboardInterrupt:
        print("\n🛑 Zatrzymuję...")
        monitor.stop()
