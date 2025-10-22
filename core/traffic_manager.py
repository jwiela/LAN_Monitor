#!/usr/bin/env python3
"""
Manager zarządzający monitoringiem ruchu i zapisem do InfluxDB
"""
import logging
import threading
import time
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


class TrafficManager:
    """Koordynuje zbieranie ruchu i zapis do bazy"""
    
    def __init__(self, app=None):
        self.app = app
        self.traffic_monitor = None
        self.influx_writer = None
        self.running = False
        self.update_thread = None
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Inicjalizacja z aplikacją Flask"""
        self.app = app
        
        # Import tutaj aby uniknąć circular imports
        from core.traffic_monitor import TrafficMonitor
        from core.influx_writer import InfluxDBWriter
        
        # Inicjalizuj monitor ruchu
        interface = app.config.get('NETWORK_INTERFACE', 'eth0')
        update_interval = app.config.get('TRAFFIC_UPDATE_INTERVAL', 60)
        self.traffic_monitor = TrafficMonitor(
            interface=interface,
            update_interval=update_interval
        )
        
        # Inicjalizuj writer do InfluxDB (jeśli włączony)
        if app.config.get('INFLUXDB_ENABLED', False):
            self.influx_writer = InfluxDBWriter(
                url=app.config.get('INFLUXDB_URL'),
                token=app.config.get('INFLUXDB_TOKEN'),
                org=app.config.get('INFLUXDB_ORG'),
                bucket=app.config.get('INFLUXDB_BUCKET')
            )
            
            if self.influx_writer.connect():
                logger.info("✅ InfluxDB writer zainicjalizowany")
            else:
                logger.warning("⚠ InfluxDB niedostępny - metryki nie będą zapisywane")
                self.influx_writer = None
        else:
            logger.info("ℹ InfluxDB wyłączony w konfiguracji")
    
    def _update_loop(self):
        """Pętla aktualizacji - pobiera statystyki i zapisuje do bazy"""
        update_interval = self.app.config.get('TRAFFIC_UPDATE_INTERVAL', 60)
        
        while self.running:
            try:
                time.sleep(update_interval)
                
                # Pobierz statystyki (z resetem)
                stats = self.traffic_monitor.get_stats(reset=True)
                
                if not stats:
                    logger.debug("Brak statystyk ruchu")
                    continue
                
                # Loguj podsumowanie
                total_devices = len(stats)
                total_bytes_in = sum(s['bytes_in'] for s in stats.values())
                total_bytes_out = sum(s['bytes_out'] for s in stats.values())
                logger.info(f"📊 Statystyki: {total_devices} urządzeń, "
                           f"↓ {total_bytes_in/1024/1024:.2f} MB, "
                           f"↑ {total_bytes_out/1024/1024:.2f} MB")
                
                # Zapisz do InfluxDB
                if self.influx_writer:
                    self.influx_writer.write_traffic_stats(stats)
                
                # Zapisz do SQLite (DeviceActivity)
                self._save_to_sqlite(stats)
                
            except Exception as e:
                logger.error(f"❌ Błąd w pętli aktualizacji: {e}", exc_info=True)
    
    def _save_to_sqlite(self, stats):
        """Zapisuje statystyki do tabeli DeviceActivity w SQLite"""
        try:
            from app import db
            from app.models import Device, DeviceActivity
            
            with self.app.app_context():
                from datetime import datetime
                
                for ip, data in stats.items():
                    # Znajdź urządzenie
                    device = Device.query.filter_by(ip_address=ip).first()
                    if not device:
                        logger.warning(f"⚠ Nie znaleziono urządzenia {ip} w bazie")
                        continue
                    
                    # Utwórz rekord aktywności (mapowanie nazw kolumn)
                    activity = DeviceActivity(
                        device_id=device.id,
                        bytes_received=data['bytes_in'],
                        bytes_sent=data['bytes_out'],
                        packets_received=data['packets_in'],
                        packets_sent=data['packets_out']
                    )
                    db.session.add(activity)
                    
                    # Aktualizuj last_seen jeśli urządzenie ma ruch
                    if data['bytes_in'] > 0 or data['bytes_out'] > 0:
                        device.last_seen = datetime.now()
                        device.is_online = True
                
                db.session.commit()
                logger.debug(f"✅ Zapisano {len(stats)} rekordów aktywności do SQLite")
                
        except Exception as e:
            logger.error(f"❌ Błąd zapisu do SQLite: {e}")
    
    def start(self):
        """Uruchamia monitoring ruchu i zapis do bazy"""
        if self.running:
            logger.warning("Traffic manager już działa!")
            return
        
        logger.info("🚀 Uruchamiam traffic manager...")
        
        # Uruchom monitor ruchu
        self.traffic_monitor.start()
        
        # Uruchom wątek aktualizacji
        self.running = True
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()
        
        logger.info("✅ Traffic manager uruchomiony")
    
    def stop(self):
        """Zatrzymuje monitoring"""
        if not self.running:
            return
        
        logger.info("🛑 Zatrzymuję traffic manager...")
        self.running = False
        
        # Zatrzymaj monitor
        if self.traffic_monitor:
            self.traffic_monitor.stop()
        
        # Poczekaj na wątek
        if self.update_thread:
            self.update_thread.join(timeout=5)
        
        # Zamknij połączenie z InfluxDB
        if self.influx_writer:
            self.influx_writer.close()
        
        logger.info("✅ Traffic manager zatrzymany")
    
    def get_device_stats(self, ip: str) -> Optional[dict]:
        """Pobiera bieżące statystyki dla konkretnego urządzenia"""
        stats = self.traffic_monitor.get_stats(reset=False)
        return stats.get(ip)


# Singleton instance
traffic_manager = TrafficManager()
