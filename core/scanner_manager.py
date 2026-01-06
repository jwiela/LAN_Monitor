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
        self.mitm_alerts_sent = {}  # Tracking wysłanych alertów o zmianie MAC
        
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
                # Wykonaj skanowanie w kontekście aplikacji
                with self.app.app_context():
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
    
    def _update_devices(self, scanned_devices, immediate_offline=False):
        """
        Aktualizuje bazę danych na podstawie zeskanowanych urządzeń
        
        Args:
            scanned_devices: Słownik z informacjami o urządzeniach {ip: info}
            immediate_offline: Jeśli True, natychmiast oznacz brakujące urządzenia jako offline
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
                        
                        # Aktualizuj MAC jeśli się zmienił - WYKRYWANIE ZMIANY MAC!
                        if info['mac'] and device.mac_address != info['mac']:
                            old_mac = device.mac_address
                            new_mac = info['mac']
                            logger.warning(f"⚠️ WYKRYTO ZMIANĘ MAC! {ip}: MAC zmienił się z {old_mac} na {new_mac}")
                            
                            # Wykryto zmianę MAC - wyślij alert
                            self._send_mac_change_alert(device, old_mac, new_mac, email_manager)
                            
                            device.mac_address = info['mac']
                        
                        # Aktualizuj vendor jeśli jest dostępny
                        if info['vendor'] and device.vendor != info['vendor']:
                            device.vendor = info['vendor']
                        
                        # Aktualizuj hostname jeśli jest dostępny
                        if info['hostname'] and device.hostname != info['hostname']:
                            device.hostname = info['hostname']
                        
                        updated_devices.append(device)
                        
                        # NIE wysyłamy powiadomień o powrocie online - tylko nowe urządzenia są alertem
                        if was_offline:
                            logger.info(f"📱 Urządzenie {device.hostname or ip} wróciło online (bez alertu)")
                    else:
                        # Dodaj nowe urządzenie
                        device = Device(
                            ip_address=ip,
                            mac_address=info['mac'],
                            vendor=info['vendor'],
                            hostname=info['hostname'],
                            is_online=True,
                            last_seen=datetime.now()
                        )
                        db.session.add(device)
                        new_devices.append(device)
                        logger.info(f"🆕 Wykryto nowe urządzenie: {device.hostname or device.vendor or ip} ({ip})")
                
                # Zapisz zmiany
                db.session.commit()
                
                # Wyślij powiadomienia o nowych urządzeniach
                for device in new_devices:
                    self._send_new_device_notification(device, email_manager)
                
                # Oznacz urządzenia jako offline jeśli nie zostały wykryte
                self._mark_missing_devices_offline(scanned_devices, immediate=immediate_offline)
                
                if new_devices:
                    logger.info(f"✅ Dodano {len(new_devices)} nowych urządzeń")
                if updated_devices:
                    logger.info(f"✅ Zaktualizowano {len(updated_devices)} urządzeń")
                
        except Exception as e:
            logger.error(f"❌ Błąd aktualizacji urządzeń: {e}", exc_info=True)
    
    def _mark_missing_devices_offline(self, scanned_devices, immediate=False):
        """
        Oznacza urządzenia jako offline jeśli nie zostały wykryte w skanowaniu
        
        Args:
            scanned_devices: Słownik ze zeskanowanymi urządzeniami {ip: info}
            immediate: Jeśli True, natychmiast oznacz jako offline bez czekania (dla ręcznego skanowania)
        """
        try:
            from app import db
            from app.models import Device
            from datetime import datetime, timedelta
            
            # Pobierz wszystkie urządzenia online
            online_devices = Device.query.filter_by(is_online=True).all()
            
            for device in online_devices:
                # Jeśli urządzenie nie zostało wykryte w skanowaniu
                if device.ip_address not in scanned_devices:
                    should_mark_offline = False
                    
                    if immediate:
                        # Dla ręcznego skanowania - natychmiastowo oznacz jako offline
                        should_mark_offline = True
                        logger.info(f"📴 Urządzenie {device.hostname or device.ip_address} nie wykryte w ręcznym skanowaniu - oznaczam jako offline")
                    elif device.last_seen:
                        # Dla automatycznego skanowania - czekaj 2 cykle
                        time_since_seen = datetime.now() - device.last_seen
                        threshold = timedelta(seconds=self.scan_interval * 2)
                        
                        if time_since_seen > threshold:
                            should_mark_offline = True
                            logger.info(f"📴 Urządzenie {device.hostname or device.ip_address} offline (brak odpowiedzi przez {time_since_seen.seconds}s)")
                    
                    if should_mark_offline:
                        device.is_online = False
                        # NIE wysyłamy powiadomień o offline - tylko nowe urządzenia są alertem
                        logger.info(f"📴 Urządzenie {device.hostname or device.ip_address} oznaczone jako offline (bez alertu)")
            
            db.session.commit()
            
        except Exception as e:
            logger.error(f"❌ Błąd oznaczania urządzeń offline: {e}", exc_info=True)
    
    def _send_new_device_notification(self, device, email_manager):
        """Wysyła powiadomienie o nowym urządzeniu"""
        try:
            from app.models import EmailRecipient, Alert
            from app import db
            
            # Utwórz alert
            message = f"Wykryto nowe urządzenie w sieci: {device.hostname or device.vendor or device.ip_address} ({device.ip_address})"
            alert = Alert(
                device_id=device.id,
                alert_type='new_device',
                message=message
            )
            db.session.add(alert)
            db.session.commit()
            
            # Wyślij emaile do odbiorców z włączonym powiadomieniem
            recipients = EmailRecipient.query.filter_by(is_active=True, notify_new_device=True).all()
            
            if recipients:
                for recipient in recipients:
                    try:
                        # Przygotuj dane urządzenia
                        device_data = {
                            'hostname': device.hostname or 'Nieznane urządzenie',
                            'ip_address': device.ip_address,
                            'mac_address': device.mac_address,
                            'vendor': device.vendor or '-',
                            'first_seen': device.first_seen.strftime('%Y-%m-%d %H:%M:%S') if device.first_seen else 'Teraz'
                        }
                        
                        # Renderuj template
                        from flask import render_template
                        html_body = render_template('emails/alert_simple.html',
                                                   alert_emoji='🆕',
                                                   message=message,
                                                   device_info=device_data,
                                                   timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                        
                        # Wyślij email
                        subject = '🆕 Nowe urządzenie w sieci'
                        email_manager.send_email(subject, html_body, to_email=recipient.email, html=True)
                        
                        logger.info(f"📧 Wysłano powiadomienie o nowym urządzeniu do {recipient.email}")
                    except Exception as e:
                        logger.error(f"❌ Błąd wysyłania emaila do {recipient.email}: {e}")
            else:
                logger.info("📧 Brak aktywnych odbiorców dla alertów o nowych urządzeniach")
                    
        except Exception as e:
            logger.error(f"❌ Błąd wysyłania powiadomienia o nowym urządzeniu: {e}", exc_info=True)
    
    def _send_online_notification(self, device, email_manager):
        """Wysyła powiadomienie o urządzeniu które wróciło online"""
        try:
            from app.models import Alert
            from app import db
            
            # Utwórz alert (bez wysyłania emaili)
            message = f"Urządzenie wróciło online: {device.hostname or device.vendor or device.ip_address} ({device.ip_address})"
            alert = Alert(
                device_id=device.id,
                alert_type='device_online',
                message=message
            )
            db.session.add(alert)
            db.session.commit()
            logger.info(f"✅ Alert online utworzony dla {device.ip_address} (bez powiadomienia email)")
                    
        except Exception as e:
            logger.error(f"❌ Błąd tworzenia alertu online: {e}", exc_info=True)
    
    def _send_offline_notification(self, device):
        """Wysyła powiadomienie o urządzeniu które przeszło offline"""
        try:
            from app.models import Alert
            from app import db
            
            # Utwórz alert (bez wysyłania emaili)
            message = f"Urządzenie offline: {device.hostname or device.vendor or device.ip_address} ({device.ip_address})"
            alert = Alert(
                device_id=device.id,
                alert_type='device_offline',
                message=message
            )
            db.session.add(alert)
            db.session.commit()
            logger.info(f"📴 Alert offline utworzony dla {device.ip_address} (bez powiadomienia email)")
                    
        except Exception as e:
            logger.error(f"❌ Błąd tworzenia alertu offline: {e}", exc_info=True)
    
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
        
        if not self.app:
            logger.error("❌ Brak aplikacji Flask - scanner_manager nie został zainicjalizowany")
            return None
        
        try:
            logger.info("🔍 Wykonuję ręczne skanowanie...")
            
            # Wykonaj w kontekście aplikacji Flask
            with self.app.app_context():
                devices = self.network_scanner.scan_network()
                
                if devices:
                    # Dla ręcznego skanowania natychmiast oznacz brakujące urządzenia jako offline
                    self._update_devices(devices, immediate_offline=True)
                    logger.info(f"✅ Ręczne skanowanie zakończone: {len(devices)} urządzeń")
                    return devices
                else:
                    logger.warning("⚠ Ręczne skanowanie nie znalazło urządzeń")
                    return {}
                
        except Exception as e:
            logger.error(f"❌ Błąd ręcznego skanowania: {e}", exc_info=True)
            return None
    
    def _send_mac_change_alert(self, device, old_mac, new_mac, email_manager):
        """
        Wysyła alert o zmianie adresu MAC
        
        Args:
            device: Obiekt Device
            old_mac: Stary adres MAC
            new_mac: Nowy adres MAC
            email_manager: Menedżer email
        """
        try:
            from app.models import EmailRecipient, Alert
            from app import db
            from datetime import datetime, timedelta
            
            # Sprawdź cooldown - nie wysyłaj alertu jeśli niedawno wysłano
            alert_key = f"mac_change_{device.ip_address}"
            if alert_key in self.mitm_alerts_sent:
                last_sent = self.mitm_alerts_sent[alert_key]
                if datetime.now() - last_sent < timedelta(hours=1):  # 1 godzina cooldown
                    logger.info(f"⏱️ Pomijam alert zmiany MAC dla {device.ip_address} (cooldown)")
                    return
            
            # Utwórz alert
            message = (f"Wykryto zmianę adresu MAC dla urządzenia {device.ip_address}.\n\n"
                      f"Szczegóły:\n"
                      f"• Stary MAC: {old_mac}\n"
                      f"• Nowy MAC: {new_mac}")
            
            alert = Alert(
                device_id=device.id,
                alert_type='mac_change',
                severity='warning',
                message=message
            )
            db.session.add(alert)
            db.session.commit()
            
            logger.warning(f"⚠️ ALERT ZMIANA MAC: {device.ip_address}: {old_mac} → {new_mac}")
            
            # Wyślij emaile do odbiorców z włączonym powiadomieniem
            recipients = EmailRecipient.query.filter_by(is_active=True, notify_mac_change=True).all()
            
            if recipients and email_manager:
                for recipient in recipients:
                    try:
                        # Przygotuj dane urządzenia
                        device_data = {
                            'hostname': device.hostname or 'Nieznane urządzenie',
                            'ip_address': device.ip_address,
                            'old_mac': old_mac,
                            'new_mac': new_mac,
                            'vendor': device.vendor or '-',
                            'detected_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        }
                        
                        # Renderuj template
                        from flask import render_template
                        html_body = render_template('emails/alert_simple.html',
                                                   alert_emoji='⚠️',
                                                   message=message,
                                                   device_info=device_data,
                                                   timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                        
                        # Wyślij email
                        email_manager.send_email(
                            to_email=recipient.email,
                            subject=f"⚠️ ALERT: Zmiana adresu MAC wykryta na {device.ip_address}",
                            body=html_body,
                            html=True
                        )
                        logger.info(f"✅ Email zmiany MAC wysłany do {recipient.email}")
                    except Exception as e:
                        logger.error(f"❌ Błąd wysyłania email zmiany MAC do {recipient.email}: {e}")
            
            # Zapisz timestamp wysłania alertu
            self.mitm_alerts_sent[alert_key] = datetime.now()
            
        except Exception as e:
            logger.error(f"❌ Błąd wysyłania alertu zmiany MAC: {e}", exc_info=True)


# Singleton instance
scanner_manager = ScannerManager()
