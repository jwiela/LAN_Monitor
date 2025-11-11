#!/usr/bin/env python3
"""
Manager zarządzający automatycznym skanowaniem sieci
"""
import logging
import threading
import time
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


class ScannerManager:
    """Koordynuje automatyczne skanowanie sieci w określonych odstępach czasu"""
    
    def __init__(self, app=None):
        self.app = app
        self.network_scanner = None
        self.running = False
        self.scan_thread = None
        self.scan_interval = 300  # domyślnie 5 minut
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Inicjalizacja z aplikacją Flask"""
        # Zabezpieczenie przed wielokrotną inicjalizacją
        if self.app is not None:
            logger.warning("⚠ Scanner manager już zainicjalizowany, pomijam ponowną inicjalizację")
            return
            
        self.app = app
        
        # Import tutaj aby uniknąć circular imports
        from core.network_scanner import NetworkScanner
        from core.email_manager import EmailManager
        from config import Config
        
        # Pobierz konfigurację
        network_range = app.config.get('NETWORK_RANGE', '192.168.1.0/24')
        self.scan_interval = app.config.get('NETWORK_SCAN_INTERVAL', 300)
        
        # Inicjalizuj network scanner
        email_manager = EmailManager(Config)
        self.network_scanner = NetworkScanner(
            network_range=network_range,
            email_manager=email_manager
        )
        
        logger.info(f"✅ Scanner Manager zainicjalizowany (range={network_range}, interval={self.scan_interval}s)")
    
    def _scan_loop(self):
        """Pętla skanowania - wykonuje skanowanie sieci w odstępach czasu"""
        logger.info(f"🔍 Rozpoczynam automatyczne skanowanie sieci co {self.scan_interval}s")
        
        while self.running:
            try:
                # Wykonaj skanowanie
                logger.info("🔍 Rozpoczynam skanowanie sieci...")
                devices = self.network_scanner.scan_network()
                
                # Zaktualizuj bazę danych
                if devices:
                    self._update_devices(devices)
                    logger.info(f"✅ Skanowanie zakończone: znaleziono {len(devices)} urządzeń")
                else:
                    logger.warning("⚠ Skanowanie nie znalazło żadnych urządzeń")
                
                # Czekaj przed następnym skanowaniem
                time.sleep(self.scan_interval)
                
            except Exception as e:
                logger.error(f"❌ Błąd w pętli skanowania: {e}", exc_info=True)
                time.sleep(60)  # Poczekaj minutę przed kolejną próbą
    
    def _update_devices(self, scanned_devices):
        """
        Aktualizuje bazę danych na podstawie zeskanowanych urządzeń
        
        Args:
            scanned_devices: Słownik z informacjami o urządzeniach {ip: info}
        """
        try:
            from app import db
            from app.models import Device, Alert, EmailRecipient
            from core.email_manager import EmailManager
            from config import Config
            
            with self.app.app_context():
                email_manager = EmailManager(Config)
                new_devices = []
                updated_devices = []
                
                for ip, info in scanned_devices.items():
                    # Sprawdź czy urządzenie już istnieje
                    device = Device.query.filter_by(ip_address=ip).first()
                    
                    if device:
                        # Aktualizuj istniejące urządzenie
                        was_offline = not device.is_online
                        device.is_online = True
                        device.last_seen = datetime.now()
                        
                        # Aktualizuj MAC jeśli się zmienił
                        if info['mac'] and device.mac_address != info['mac']:
                            device.mac_address = info['mac']
                        
                        # Aktualizuj vendor jeśli jest dostępny
                        if info['vendor'] and device.vendor != info['vendor']:
                            device.vendor = info['vendor']
                        
                        # Aktualizuj hostname jeśli jest dostępny
                        if info['hostname'] and device.hostname != info['hostname']:
                            device.hostname = info['hostname']
                        
                        updated_devices.append(device)
                        
                        # Jeśli urządzenie było offline, wyślij powiadomienie
                        if was_offline:
                            logger.info(f"📱 Urządzenie {device.name or ip} wróciło online")
                            self._send_online_notification(device, email_manager)
                    else:
                        # Dodaj nowe urządzenie
                        device = Device(
                            ip_address=ip,
                            mac_address=info['mac'],
                            vendor=info['vendor'],
                            hostname=info['hostname'],
                            name=info['hostname'] or info['vendor'] or f"Device {ip}",
                            is_online=True,
                            last_seen=datetime.now()
                        )
                        db.session.add(device)
                        new_devices.append(device)
                        logger.info(f"🆕 Wykryto nowe urządzenie: {device.name} ({ip})")
                
                # Zapisz zmiany
                db.session.commit()
                
                # Wyślij powiadomienia o nowych urządzeniach
                for device in new_devices:
                    self._send_new_device_notification(device, email_manager)
                
                # Oznacz urządzenia jako offline jeśli nie zostały wykryte
                self._mark_missing_devices_offline(scanned_devices)
                
                if new_devices:
                    logger.info(f"✅ Dodano {len(new_devices)} nowych urządzeń")
                if updated_devices:
                    logger.info(f"✅ Zaktualizowano {len(updated_devices)} urządzeń")
                
        except Exception as e:
            logger.error(f"❌ Błąd aktualizacji urządzeń: {e}", exc_info=True)
    
    def _mark_missing_devices_offline(self, scanned_devices):
        """Oznacza urządzenia jako offline jeśli nie zostały wykryte w skanowaniu"""
        try:
            from app import db
            from app.models import Device
            from datetime import datetime, timedelta
            
            # Pobierz wszystkie urządzenia online
            online_devices = Device.query.filter_by(is_online=True).all()
            
            for device in online_devices:
                # Jeśli urządzenie nie zostało wykryte w skanowaniu
                if device.ip_address not in scanned_devices:
                    # Sprawdź czy minęło wystarczająco dużo czasu (2 * scan_interval)
                    if device.last_seen:
                        time_since_seen = datetime.now() - device.last_seen
                        threshold = timedelta(seconds=self.scan_interval * 2)
                        
                        if time_since_seen > threshold:
                            logger.info(f"📴 Urządzenie {device.name or device.ip_address} offline")
                            device.is_online = False
                            self._send_offline_notification(device)
            
            db.session.commit()
            
        except Exception as e:
            logger.error(f"❌ Błąd oznaczania urządzeń offline: {e}", exc_info=True)
    
    def _send_new_device_notification(self, device, email_manager):
        """Wysyła powiadomienie o nowym urządzeniu"""
        try:
            from app.models import EmailRecipient, Alert
            from app import db
            
            # Utwórz alert
            message = f"Wykryto nowe urządzenie w sieci: {device.name} ({device.ip_address})"
            alert = Alert(
                device_id=device.id,
                alert_type='new_device',
                message=message
            )
            db.session.add(alert)
            db.session.commit()
            
            # Wyślij emaile do odbiorców z włączonym powiadomieniem
            recipients = EmailRecipient.query.filter_by(notify_new_device=True).all()
            
            for recipient in recipients:
                try:
                    email_manager.send_alert(
                        to_email=recipient.email,
                        alert_type='new_device',
                        message=message,
                        device_info={
                            'name': device.name,
                            'ip': device.ip_address,
                            'mac': device.mac_address,
                            'vendor': device.vendor
                        }
                    )
                    logger.info(f"📧 Wysłano powiadomienie o nowym urządzeniu do {recipient.email}")
                except Exception as e:
                    logger.error(f"❌ Błąd wysyłania emaila do {recipient.email}: {e}")
                    
        except Exception as e:
            logger.error(f"❌ Błąd wysyłania powiadomienia o nowym urządzeniu: {e}", exc_info=True)
    
    def _send_online_notification(self, device, email_manager):
        """Wysyła powiadomienie o urządzeniu które wróciło online"""
        try:
            from app.models import EmailRecipient, Alert
            from app import db
            
            # Utwórz alert
            message = f"Urządzenie wróciło online: {device.name} ({device.ip_address})"
            alert = Alert(
                device_id=device.id,
                alert_type='device_online',
                message=message
            )
            db.session.add(alert)
            db.session.commit()
            
            # Wyślij emaile do odbiorców z włączonym powiadomieniem
            recipients = EmailRecipient.query.filter_by(notify_device_online=True).all()
            
            for recipient in recipients:
                try:
                    email_manager.send_alert(
                        to_email=recipient.email,
                        alert_type='device_online',
                        message=message,
                        device_info={
                            'name': device.name,
                            'ip': device.ip_address,
                            'mac': device.mac_address,
                            'vendor': device.vendor
                        }
                    )
                    logger.info(f"📧 Wysłano powiadomienie o urządzeniu online do {recipient.email}")
                except Exception as e:
                    logger.error(f"❌ Błąd wysyłania emaila do {recipient.email}: {e}")
                    
        except Exception as e:
            logger.error(f"❌ Błąd wysyłania powiadomienia online: {e}", exc_info=True)
    
    def _send_offline_notification(self, device):
        """Wysyła powiadomienie o urządzeniu które przeszło offline"""
        try:
            from app.models import EmailRecipient, Alert
            from app import db
            from core.email_manager import EmailManager
            from config import Config
            
            email_manager = EmailManager(Config)
            
            # Utwórz alert
            message = f"Urządzenie offline: {device.name} ({device.ip_address})"
            alert = Alert(
                device_id=device.id,
                alert_type='device_offline',
                message=message
            )
            db.session.add(alert)
            db.session.commit()
            
            # Wyślij emaile do odbiorców z włączonym powiadomieniem
            recipients = EmailRecipient.query.filter_by(notify_device_offline=True).all()
            
            for recipient in recipients:
                try:
                    email_manager.send_alert(
                        to_email=recipient.email,
                        alert_type='device_offline',
                        message=message,
                        device_info={
                            'name': device.name,
                            'ip': device.ip_address,
                            'mac': device.mac_address,
                            'vendor': device.vendor
                        }
                    )
                    logger.info(f"📧 Wysłano powiadomienie o urządzeniu offline do {recipient.email}")
                except Exception as e:
                    logger.error(f"❌ Błąd wysyłania emaila do {recipient.email}: {e}")
                    
        except Exception as e:
            logger.error(f"❌ Błąd wysyłania powiadomienia offline: {e}", exc_info=True)
    
    def start(self):
        """Uruchamia automatyczne skanowanie sieci"""
        if self.running:
            logger.warning("Scanner manager już działa!")
            return
        
        if not self.app.config.get('NETWORK_SCAN_ENABLED', True):
            logger.info("ℹ Automatyczne skanowanie sieci jest wyłączone w konfiguracji")
            return
        
        logger.info("🚀 Uruchamiam scanner manager...")
        
        # Uruchom wątek skanowania
        self.running = True
        self.scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.scan_thread.start()
        
        logger.info("✅ Scanner manager uruchomiony")
    
    def stop(self):
        """Zatrzymuje automatyczne skanowanie"""
        if not self.running:
            return
        
        logger.info("🛑 Zatrzymuję scanner manager...")
        self.running = False
        
        # Poczekaj na wątek
        if self.scan_thread:
            self.scan_thread.join(timeout=5)
        
        logger.info("✅ Scanner manager zatrzymany")
    
    def trigger_scan(self):
        """Wymusza natychmiastowe skanowanie (do ręcznego wywołania)"""
        if not self.network_scanner:
            logger.error("❌ Network scanner nie jest zainicjalizowany")
            return None
        
        try:
            logger.info("🔍 Wykonuję ręczne skanowanie...")
            devices = self.network_scanner.scan_network()
            
            if devices:
                self._update_devices(devices)
                logger.info(f"✅ Ręczne skanowanie zakończone: {len(devices)} urządzeń")
                return devices
            else:
                logger.warning("⚠ Ręczne skanowanie nie znalazło urządzeń")
                return {}
                
        except Exception as e:
            logger.error(f"❌ Błąd ręcznego skanowania: {e}", exc_info=True)
            return None


# Singleton instance
scanner_manager = ScannerManager()
