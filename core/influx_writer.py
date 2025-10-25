#!/usr/bin/env python3
"""
Moduł integracji z InfluxDB
Zapisuje metryki ruchu sieciowego do bazy czasowej
"""
import logging
from datetime import datetime
from typing import Dict, Optional
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

logger = logging.getLogger(__name__)


class InfluxDBWriter:
    """Zarządza połączeniem i zapisem metryk do InfluxDB"""
    
    def __init__(self, url='http://localhost:8086', token='', org='lan_monitor', bucket='network_traffic'):
        """
        Args:
            url: URL serwera InfluxDB
            token: Token autoryzacyjny (pozostaw puste dla setup mode)
            org: Nazwa organizacji
            bucket: Nazwa bucket (bazy danych)
        """
        self.url = url
        self.token = token
        self.org = org
        self.bucket = bucket
        self.client = None
        self.write_api = None
        
    def connect(self) -> bool:
        """
        Nawiązuje połączenie z InfluxDB
        
        Returns:
            True jeśli połączenie udane
        """
        try:
            self.client = InfluxDBClient(url=self.url, token=self.token, org=self.org)
            self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
            
            # Test połączenia
            health = self.client.health()
            if health.status == "pass":
                logger.info(f"✅ Połączono z InfluxDB: {self.url}")
                return True
            else:
                logger.error(f"❌ InfluxDB nie jest gotowy: {health.status}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Błąd połączenia z InfluxDB: {e}")
            return False
    
    def write_traffic_stats(self, stats: Dict[str, Dict[str, int]], timestamp: Optional[datetime] = None):
        """
        Zapisuje statystyki ruchu do InfluxDB
        
        Args:
            stats: Słownik {ip: {'bytes_in': int, 'bytes_out': int, ...}}
            timestamp: Timestamp danych (domyślnie: teraz)
        """
        if not self.write_api:
            logger.warning("Brak połączenia z InfluxDB - pomijam zapis")
            return
        
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        try:
            points = []
            
            for ip, data in stats.items():
                # Point dla ruchu przychodzącego
                point_in = Point("traffic") \
                    .tag("ip", ip) \
                    .tag("direction", "in") \
                    .field("bytes", int(data['bytes_in'])) \
                    .field("packets", int(data['packets_in'])) \
                    .time(timestamp, WritePrecision.NS)
                points.append(point_in)
                
                # Point dla ruchu wychodzącego
                point_out = Point("traffic") \
                    .tag("ip", ip) \
                    .tag("direction", "out") \
                    .field("bytes", int(data['bytes_out'])) \
                    .field("packets", int(data['packets_out'])) \
                    .time(timestamp, WritePrecision.NS)
                points.append(point_out)
            
            # Zapis batch
            logger.debug(f"📝 Zapisuję {len(points)} punktów: bucket={self.bucket}, org={self.org}")
            logger.debug(f"   Przykładowy punkt: {points[0] if points else 'brak'}")
            self.write_api.write(bucket=self.bucket, org=self.org, record=points)
            logger.info(f"✅ Zapisano {len(points)} punktów danych do InfluxDB (bucket={self.bucket}, org={self.org})")
            
        except Exception as e:
            logger.error(f"❌ Błąd zapisu do InfluxDB: {e}", exc_info=True)
            logger.error(f"   Bucket: {self.bucket}, Org: {self.org}")
    
    def write_device_metric(self, ip: str, metric_name: str, value: float, tags: Optional[Dict] = None):
        """
        Zapisuje pojedynczą metrykę dla urządzenia
        
        Args:
            ip: Adres IP urządzenia
            metric_name: Nazwa metryki (np. 'bandwidth', 'latency')
            value: Wartość metryki
            tags: Dodatkowe tagi (opcjonalnie)
        """
        if not self.write_api:
            return
        
        try:
            point = Point("device_metric") \
                .tag("ip", ip) \
                .tag("metric", metric_name)
            
            if tags:
                for key, val in tags.items():
                    point.tag(key, val)
            
            point.field("value", value)
            
            self.write_api.write(bucket=self.bucket, org=self.org, record=point)
            logger.debug(f"✅ Zapisano metrykę {metric_name} dla {ip}: {value}")
            
        except Exception as e:
            logger.error(f"❌ Błąd zapisu metryki: {e}")
    
    def close(self):
        """Zamyka połączenie z InfluxDB"""
        if self.client:
            self.client.close()
            logger.info("🔌 Rozłączono z InfluxDB")


if __name__ == '__main__':
    # Test modułu
    logging.basicConfig(level=logging.INFO)
    
    # Przykładowe dane
    test_stats = {
        '192.168.1.100': {'bytes_in': 1024000, 'bytes_out': 512000, 'packets_in': 1000, 'packets_out': 500},
        '192.168.1.101': {'bytes_in': 2048000, 'bytes_out': 1024000, 'packets_in': 2000, 'packets_out': 1000},
    }
    
    writer = InfluxDBWriter()
    if writer.connect():
        writer.write_traffic_stats(test_stats)
        writer.close()
