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
        
        # Parametry wykrywania DDoS
        self.ddos_threshold_multiplier = 3.0  # Ruch > 3x średnia = potencjalny DDoS (obniżone z 5x)
        self.ddos_min_packets = 5000  # Minimalna liczba pakietów/min do uznania za DDoS (obniżone z 10000)
        self.device_baselines = {}  # Średnie wartości ruchu dla urządzeń
        self.ddos_alerts_sent = {}  # Tracking wysłanych alertów (aby nie spamować)
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Inicjalizacja z aplikacją Flask"""
        # Zabezpieczenie przed wielokrotną inicjalizacją
        if self.app is not None:
            logger.warning("⚠ Traffic manager już zainicjalizowany, pomijam ponowną inicjalizację")
            return
            
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
        
        logger.info(f"✅ Traffic manager zainicjalizowany (interface={interface}, interval={update_interval}s)")
        
        # Inicjalizuj writer do InfluxDB (jeśli włączony)
        if app.config.get('INFLUXDB_ENABLED', False):
            influx_url = app.config.get('INFLUXDB_URL')
            influx_token = app.config.get('INFLUXDB_TOKEN')
            influx_org = app.config.get('INFLUXDB_ORG')
            influx_bucket = app.config.get('INFLUXDB_BUCKET')
            logger.info(f"🔧 InfluxDB Config: url={influx_url}, org={influx_org}, bucket={influx_bucket}")
            self.influx_writer = InfluxDBWriter(
                url=influx_url,
                token=influx_token,
                org=influx_org,
                bucket=influx_bucket
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
        logger.info(f"▶️ Uruchomiono pętlę aktualizacji, interwał: {update_interval}s")
        
        while self.running:
            try:
                logger.info("🔄 Rozpoczęcie cyklu aktualizacji...")
                
                # Pobierz statystyki (z resetem)
                stats = self.traffic_monitor.get_stats(reset=True)
                logger.info(f"📊 Pobrano statystyki dla {len(stats)} urządzeń")
                
                if not stats:
                    logger.debug("Brak statystyk ruchu")
                    time.sleep(update_interval)
                    continue
                
                # Oblicz i loguj podsumowanie
                total_devices = len(stats)
                total_bytes_in = sum(s['bytes_in'] for s in stats.values())
                total_bytes_out = sum(s['bytes_out'] for s in stats.values())
                total_packets_in = sum(s['packets_in'] for s in stats.values())
                total_packets_out = sum(s['packets_out'] for s in stats.values())
                
                logger.info(f"📊 Statystyki: {total_devices} urządzeń, "
                           f"↓ {total_bytes_in/1024/1024:.2f} MB, "
                           f"↑ {total_bytes_out/1024/1024:.2f} MB")
                
                # Zapisz do InfluxDB
                if self.influx_writer:
                    # Zapisz statystyki per urządzenie
                    self.influx_writer.write_traffic_stats(stats)
                    
                    # Zapisz całkowite statystyki
                    total_stats = {
                        'total_bytes_in': total_bytes_in,
                        'total_bytes_out': total_bytes_out,
                        'total_packets_in': total_packets_in,
                        'total_packets_out': total_packets_out,
                        'device_count': total_devices
                    }
                    self.influx_writer.write_total_traffic(total_stats)
                
                # Zapisz do SQLite (DeviceActivity)
                self._save_to_sqlite(stats)
                
                # Sprawdź czy nie ma potencjalnego ataku DDoS
                self._check_for_ddos(stats)
                
                # Czekaj przed następnym cyklem
                time.sleep(update_interval)
                
            except Exception as e:
                logger.error(f"❌ Błąd w pętli aktualizacji: {e}", exc_info=True)
                time.sleep(update_interval)
    
    def _check_for_ddos(self, stats):
        """
        Sprawdza czy wykryto potencjalny atak DDoS
        
        Kryteria:
        - Liczba pakietów przychodzących > ddos_min_packets w ciągu update_interval
        - Ruch przychodzący > ddos_threshold_multiplier * średnia historyczna
        """
        try:
            from app import db
            from app.models import Device, Alert, EmailRecipient
            from flask import render_template
            import time
            
            logger.info(f"🔍 Sprawdzam DDoS dla {len(stats)} urządzeń...")
            
            with self.app.app_context():
                current_time = time.time()
                
                for ip, data in stats.items():
                    packets_in = data.get('packets_in', 0)
                    bytes_in = data.get('bytes_in', 0)
                    
                    # Sprawdź czy przekroczono minimalny próg pakietów
                    update_interval = self.app.config.get('TRAFFIC_UPDATE_INTERVAL', 60)
                    packets_per_minute = (packets_in / update_interval) * 60
                    
                    logger.info(f"  {ip}: {packets_in} pakietów ({packets_per_minute:.0f}/min, próg: {self.ddos_min_packets})")
                    
                    if packets_per_minute < self.ddos_min_packets:
                        continue
                    
                    logger.info(f"⚠️ {ip} przekroczył próg pakietów: {packets_per_minute:.0f}/min > {self.ddos_min_packets}")
                    
                    # Pobierz lub utwórz baseline dla urządzenia
                    if ip not in self.device_baselines:
                        self.device_baselines[ip] = {
                            'avg_packets_in': packets_in,
                            'avg_bytes_in': bytes_in,
                            'samples': 1
                        }
                        logger.info(f"📊 Utworzono baseline dla {ip}: {packets_in} pakietów")
                        continue  # Pierwszy pomiar, brak historii
                    
                    baseline = self.device_baselines[ip]
                    avg_packets = baseline['avg_packets_in']
                    
                    # Sprawdź czy ruch przekracza próg (5x średnia)
                    if packets_in > avg_packets * self.ddos_threshold_multiplier:
                        # Sprawdź czy nie wysłaliśmy już alertu w ostatnich 10 minutach
                        last_alert_time = self.ddos_alerts_sent.get(ip, 0)
                        if current_time - last_alert_time < 600:  # 10 minut
                            continue
                        
                        # Potencjalny DDoS wykryty!
                        device = Device.query.filter_by(ip_address=ip).first()
                        
                        if device:
                            logger.warning(f"🚨 Potencjalny atak DDoS wykryty na {ip}! "
                                         f"Pakiety: {packets_in} (średnia: {avg_packets:.0f})")
                            
                            # Utwórz alert w bazie
                            alert = Alert(
                                device_id=device.id,
                                alert_type='ddos_attack',
                                severity='critical',
                                message=f"Wykryto nietypowo wysoki ruch przychodzący na urządzeniu {device.hostname or device.ip_address}. "
                                       f"Liczba pakietów: {packets_in:,} ({packets_per_minute:.0f}/min), "
                                       f"co jest {(packets_in/avg_packets):.1f}x większe niż średnia historyczna."
                            )
                            db.session.add(alert)
                            db.session.commit()
                            
                            # Wyślij powiadomienia email
                            recipients = EmailRecipient.query.filter_by(is_active=True).all()
                            active_recipients = [r for r in recipients if r.should_notify('ddos_attack')]
                            
                            if active_recipients:
                                from core.email_manager import EmailManager
                                from config import Config
                                email_manager = EmailManager(Config)
                                
                                device_info = {
                                    'ip': device.ip_address,
                                    'hostname': device.hostname or 'Nieznany',
                                    'vendor': device.vendor or 'Nieznany',
                                    'packets_in': f"{packets_in:,}",
                                    'packets_per_min': f"{packets_per_minute:.0f}",
                                    'bytes_in': f"{bytes_in / (1024*1024):.2f} MB",
                                    'threshold': f"{(packets_in/avg_packets):.1f}x średnia"
                                }
                                
                                message = (
                                    f"Wykryto potencjalny atak DDoS na urządzeniu {device.hostname or device.ip_address} ({device.ip_address}).\n\n"
                                    f"Szczegóły:\n"
                                    f"• Liczba pakietów przychodzących: {packets_in:,}\n"
                                    f"• Intensywność: {packets_per_minute:.0f} pakietów/min\n"
                                    f"• Ruch przychodzący: {bytes_in / (1024*1024):.2f} MB\n"
                                    f"• Stosunek do średniej: {(packets_in/avg_packets):.1f}x\n\n"
                                    f"Sprawdź urządzenie i podejmij odpowiednie działania."
                                )
                                
                                for recipient in active_recipients:
                                    try:
                                        html_body = render_template('emails/alert_simple.html',
                                                                   alert_emoji='🚨',
                                                                   message=message,
                                                                   device_info=device_info,
                                                                   timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                                        
                                        email_manager.send_email(
                                            subject='🚨 ALERT: Potencjalny atak DDoS wykryty!',
                                            body=html_body,
                                            to_email=recipient.email,
                                            html=True
                                        )
                                        logger.info(f"📧 Alert DDoS wysłany do {recipient.email}")
                                    except Exception as e:
                                        logger.error(f"❌ Błąd wysyłania alertu DDoS do {recipient.email}: {e}")
                                
                                # Zaznacz czas wysłania alertu
                                self.ddos_alerts_sent[ip] = current_time
                            else:
                                logger.info("📧 Brak aktywnych odbiorców dla alertów DDoS")
                    
                    # Aktualizuj baseline (exponential moving average)
                    baseline['avg_packets_in'] = (baseline['avg_packets_in'] * 0.9) + (packets_in * 0.1)
                    baseline['avg_bytes_in'] = (baseline['avg_bytes_in'] * 0.9) + (bytes_in * 0.1)
                    baseline['samples'] += 1
                    
        except Exception as e:
            logger.error(f"❌ Błąd sprawdzania DDoS: {e}", exc_info=True)
    
    def _save_to_sqlite(self, stats):
        """Zapisuje statystyki do tabeli DeviceActivity w SQLite"""
        try:
            from app import db
            from app.models import Device, DeviceActivity
            import json
            
            with self.app.app_context():
                from datetime import datetime
                
                for ip, data in stats.items():
                    # Znajdź urządzenie
                    device = Device.query.filter_by(ip_address=ip).first()
                    if not device:
                        logger.warning(f"⚠ Nie znaleziono urządzenia {ip} w bazie")
                        continue
                    
                    # Przygotuj dane protokołów jako JSON
                    protocol_stats_json = None
                    if 'protocols' in data and data['protocols']:
                        protocol_stats_json = json.dumps(data['protocols'])
                    
                    # Utwórz rekord aktywności (mapowanie nazw kolumn)
                    activity = DeviceActivity(
                        device_id=device.id,
                        bytes_received=data['bytes_in'],
                        bytes_sent=data['bytes_out'],
                        packets_received=data['packets_in'],
                        packets_sent=data['packets_out'],
                        protocol_stats=protocol_stats_json
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
        logger.info("🧵 Tworzę wątek aktualizacji...")
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()
        logger.info(f"🧵 Wątek uruchomiony: alive={self.update_thread.is_alive()}")
        
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
    
    def get_total_stats(self) -> dict:
        """Pobiera zsumowane statystyki ze wszystkich urządzeń oraz aktualne prędkości"""
        stats = self.traffic_monitor.get_stats(reset=False)
        
        if not stats:
            return {
                'total_bytes_in': 0,
                'total_bytes_out': 0,
                'total_packets_in': 0,
                'total_packets_out': 0,
                'device_count': 0,
                'download_rate': 0.0,
                'upload_rate': 0.0
            }
        
        total_bytes_in = sum(s['bytes_in'] for s in stats.values())
        total_bytes_out = sum(s['bytes_out'] for s in stats.values())
        total_packets_in = sum(s['packets_in'] for s in stats.values())
        total_packets_out = sum(s['packets_out'] for s in stats.values())
        
        # Pobierz aktualne prędkości dla wszystkich urządzeń
        download_rate = 0.0
        upload_rate = 0.0
        
        if self.traffic_monitor and self.traffic_monitor.running:
            try:
                rates = self.traffic_monitor.get_current_rates()
                # Zsumuj prędkości wszystkich urządzeń
                for ip, (down, up) in rates.items():
                    download_rate += down
                    upload_rate += up
            except Exception as e:
                logger.error(f"❌ Błąd pobierania rates: {e}")
        
        return {
            'total_bytes_in': total_bytes_in,
            'total_bytes_out': total_bytes_out,
            'total_packets_in': total_packets_in,
            'total_packets_out': total_packets_out,
            'device_count': len(stats),
            'download_rate': download_rate,
            'upload_rate': upload_rate
        }


# Singleton instance
traffic_manager = TrafficManager()
