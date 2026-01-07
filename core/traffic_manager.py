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
        
        # Parametry wykrywania podejrzanego ruchu
        self.traffic_threshold_mbps = 80  # Próg ruchu w Mbps (80 Mbps = 10 MB/s)
        self.traffic_min_packets = 50000  # Minimalna liczba pakietów/min do uznania za podejrzany ruch
        self.suspicious_alerts_sent = {}  # Tracking wysłanych alertów (aby nie spamować)
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Inicjalizacja z aplikacją Flask"""
        # Zabezpieczenie przed wielokrotną inicjalizacją tego samego managera
        if self.traffic_monitor is not None:
            logger.warning("⚠ Traffic manager już posiada monitor, pomijam ponowną inicjalizację")
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
        logger.info(f"⏳ Czekam {update_interval}s na zebranie pierwszych statystyk...")
        
        while self.running:
            try:
                # Najpierw czekaj, żeby monitor zebrał dane
                time.sleep(update_interval)
                
                logger.info("🔄 Rozpoczęcie cyklu aktualizacji...")
                
                # Pobierz statystyki (z resetem)
                stats = self.traffic_monitor.get_stats(reset=True)
                logger.info(f"📊 Pobrano statystyki dla {len(stats)} urządzeń")
                
                # Zawsze wywołuj sprawdzanie, nawet jeśli stats jest puste (dla debugowania)
                if stats:
                    logger.info(f"📋 Urządzenia w statystykach: {list(stats.keys())}")
                else:
                    logger.warning("⚠️ Brak statystyk ruchu - monitor może nie zbierać danych!")
                
                if not stats:
                    logger.debug("Brak statystyk ruchu - przeskakuję do następnego cyklu")
                    # NADAL SPRAWDZAMY ALERTY (na wypadek gdyby stats było puste)
                    self._check_for_suspicious_traffic(stats)
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
                
                # Sprawdź czy nie ma podejrzanego ruchu sieciowego
                self._check_for_suspicious_traffic(stats)
                
            except Exception as e:
                logger.error(f"❌ Błąd w pętli aktualizacji: {e}", exc_info=True)
                time.sleep(update_interval)
    
    def _check_for_suspicious_traffic(self, stats):
        """
        Sprawdza czy wykryto podejrzany ruch sieciowy
        
        Kryteria:
        - Liczba pakietów przychodzących > traffic_min_packets w ciągu update_interval
        - Prędkość ruchu przychodzącego > traffic_threshold_mbps
        """
        try:
            from app import db
            from app.models import Device, Alert, EmailRecipient
            from flask import render_template
            import time
            
            logger.info(f"🔍 === SPRAWDZANIE PODEJRZANEGO RUCHU ===")
            logger.info(f"🔍 Liczba urządzeń do sprawdzenia: {len(stats)}")
            logger.info(f"🔍 Progi: {self.traffic_threshold_mbps} Mbps, {self.traffic_min_packets} pkt/min")
            
            if not stats:
                logger.info(f"🔍 Brak statystyk - monitor może nie zbierać danych lub brak ruchu")
                return
            
            with self.app.app_context():
                current_time = time.time()
                update_interval = self.app.config.get('TRAFFIC_UPDATE_INTERVAL', 60)
                
                for ip, data in stats.items():
                    packets_in = data.get('packets_in', 0)
                    bytes_in = data.get('bytes_in', 0)
                    
                    # Oblicz prędkość w Mbps
                    bytes_per_second = bytes_in / update_interval
                    mbps = (bytes_per_second * 8) / (1024 * 1024)  # Konwersja na Mbps
                    
                    # Oblicz pakiety na minutę
                    packets_per_minute = (packets_in / update_interval) * 60
                    
                    logger.info(f"  🔍 {ip}: {packets_in} pakietów ({packets_per_minute:.0f}/min), "
                               f"{mbps:.1f} Mbps (próg: {self.traffic_threshold_mbps} Mbps, "
                               f"{self.traffic_min_packets} pkt/min)")
                    
                    # Sprawdź czy przekroczono KTÓRYKOLWIEK z progów (LUB, nie I)
                    packets_exceeded = packets_per_minute >= self.traffic_min_packets
                    mbps_exceeded = mbps >= self.traffic_threshold_mbps
                    
                    if not packets_exceeded and not mbps_exceeded:
                        logger.info(f"  ⏭️ {ip}: Nie przekroczono żadnego progu (pakiety: {packets_per_minute:.0f}/{self.traffic_min_packets}, Mbps: {mbps:.1f}/{self.traffic_threshold_mbps})")
                        continue
                    
                    # Loguj który próg został przekroczony
                    exceeded_info = []
                    if packets_exceeded:
                        exceeded_info.append(f"pakiety: {packets_per_minute:.0f} >= {self.traffic_min_packets}")
                    if mbps_exceeded:
                        exceeded_info.append(f"Mbps: {mbps:.1f} >= {self.traffic_threshold_mbps}")
                    
                    logger.warning(f"⚠️ {ip} przekroczył progi: {' | '.join(exceeded_info)}")
                    
                    # Cooldown - nie wysyłaj alertu jeśli niedawno wysłano
                    last_alert_time = self.suspicious_alerts_sent.get(ip, 0)
                    time_since_last = (current_time - last_alert_time) / 60  # w minutach
                    if current_time - last_alert_time < 1800:  # 30 minut
                        logger.info(f"⏭️ {ip}: Alert już wysłany {time_since_last:.1f} min temu, pomijam (cooldown: 30 min)")
                        continue
                    
                    if last_alert_time > 0:
                        logger.info(f"✅ {ip}: Cooldown minął ({time_since_last:.1f} min), wysyłam alert")
                    
                    # Podejrzany ruch wykryty!
                    device = Device.query.filter_by(ip_address=ip).first()
                    
                    if not device:
                        logger.error(f"❌ {ip}: Nie znaleziono urządzenia w bazie danych!")
                        continue
                    
                    logger.warning(f"🚨 Podejrzany ruch sieciowy wykryty na {ip}! "
                                 f"Prędkość: {mbps:.1f} Mbps, Pakiety: {packets_per_minute:.0f}/min")
                    
                    # Utwórz alert w bazie
                    alert = Alert(
                        device_id=device.id,
                        alert_type='suspicious_traffic',
                        severity='warning',
                        message=f"Wykryto podejrzanie wysoki ruch sieciowy na urządzeniu {device.hostname or device.ip_address}. "
                               f"Prędkość: {mbps:.1f} Mbps, "
                               f"Liczba pakietów: {packets_per_minute:.0f}/min."
                    )
                    db.session.add(alert)
                    db.session.commit()
                    
                    # Wyślij powiadomienia email
                    recipients = EmailRecipient.query.filter_by(is_active=True).all()
                    active_recipients = [r for r in recipients if r.should_notify('suspicious_traffic')]
                    
                    logger.info(f"📧 Znaleziono {len(recipients)} odbiorców, aktywnych dla suspicious_traffic: {len(active_recipients)}")
                    
                    if active_recipients:
                        logger.info(f"📧 Wysyłam alerty o podejrzanym ruchu do: {[r.email for r in active_recipients]}")
                        from core.email_manager import EmailManager
                        from config import Config
                        email_manager = EmailManager(Config)
                        
                        device_info = {
                            'ip': device.ip_address,
                            'hostname': device.hostname or 'Nieznany',
                            'vendor': device.vendor or 'Nieznany',
                            'packets_per_min': f"{packets_per_minute:.0f}",
                            'speed_mbps': f"{mbps:.1f} Mbps",
                            'threshold': f"{self.traffic_threshold_mbps} Mbps"
                        }
                        
                        message = (
                            f"Wykryto podejrzanie wysoki ruch sieciowy na urządzeniu {device.ip_address}.\n\n"
                            f"Szczegóły:\n"
                            f"• Intensywność: {packets_per_minute:.0f} pakietów/min\n\n"
                            f". Sprawdź urządzenie jeśli ruch jest nieoczekiwany."
                        )
                        
                        for recipient in active_recipients:
                            try:
                                html_body = render_template('emails/alert_simple.html',
                                                           alert_emoji='⚠️',
                                                           message=message,
                                                           device_info=device_info,
                                                           timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                                
                                email_manager.send_email(
                                    subject='⚠️ ALERT: Wykryto podejrzany ruch sieciowy',
                                    body=html_body,
                                    to_email=recipient.email,
                                    html=True
                                )
                                logger.info(f"📧 Alert wysłany do {recipient.email}")
                            except Exception as e:
                                logger.error(f"❌ Błąd wysyłania alertu do {recipient.email}: {e}")
                        
                        # Zaznacz czas wysłania alertu
                        self.suspicious_alerts_sent[ip] = current_time
                    else:
                        logger.info("📧 Brak aktywnych odbiorców dla alertów o podejrzanym ruchu")
                    
        except Exception as e:
            logger.error(f"❌ Błąd sprawdzania podejrzanego ruchu: {e}", exc_info=True)
    
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
