"""
Menedżer wysyłania powiadomień email
"""
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional, List
from config import Config

logger = logging.getLogger(__name__)


class EmailManager:
    """Klasa do zarządzania wysyłaniem powiadomień email"""
    
    def __init__(self, config: Config):
        """
        Inicjalizacja menedżera email
        
        Args:
            config: Obiekt konfiguracji aplikacji
        """
        self.config = config
        self.enabled = bool(config.MAIL_SERVER and 
                          config.MAIL_USERNAME and 
                          config.MAIL_PASSWORD and 
                          config.ALERT_EMAIL)
        
        if self.enabled:
            logger.info(f"📧 Email manager zainicjalizowany: {config.MAIL_SERVER}:{config.MAIL_PORT}")
        else:
            logger.warning("⚠️ Email manager wyłączony - brak konfiguracji SMTP")
    
    def send_email(self, subject: str, body: str, to_email: Optional[str] = None, html: bool = False, 
                   attachment: bytes = None, attachment_name: str = None) -> bool:
        """
        Wyślij email
        
        Args:
            subject: Temat wiadomości
            body: Treść wiadomości
            to_email: Adres odbiorcy (opcjonalnie, domyślnie ALERT_EMAIL)
            html: Czy treść jest w formacie HTML
            attachment: Dane załącznika (bytes)
            attachment_name: Nazwa pliku załącznika
            
        Returns:
            bool: True jeśli wysłano pomyślnie
        """
        if not self.enabled:
            logger.warning("⚠️ Próba wysłania emaila, ale email manager jest wyłączony")
            return False
        
        try:
            # Użyj domyślnego adresu jeśli nie podano
            recipient = to_email or self.config.ALERT_EMAIL
            
            if not recipient:
                logger.error("❌ Brak adresu odbiorcy")
                return False
            
            # Przygotuj wiadomość
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.config.MAIL_DEFAULT_SENDER or self.config.MAIL_USERNAME
            msg['To'] = recipient
            
            # Dodaj treść
            if html:
                msg.attach(MIMEText(body, 'html', 'utf-8'))
            else:
                msg.attach(MIMEText(body, 'plain', 'utf-8'))
            
            # Dodaj załącznik jeśli jest
            if attachment and attachment_name:
                from email.mime.application import MIMEApplication
                part = MIMEApplication(attachment, Name=attachment_name)
                part['Content-Disposition'] = f'attachment; filename="{attachment_name}"'
                msg.attach(part)
            
            # Połącz się z serwerem SMTP
            with smtplib.SMTP(self.config.MAIL_SERVER, self.config.MAIL_PORT, timeout=30) as server:
                server.set_debuglevel(0)
                
                if self.config.MAIL_USE_TLS:
                    server.starttls()
                
                server.login(self.config.MAIL_USERNAME, self.config.MAIL_PASSWORD)
                result = server.send_message(msg)
                
                if result:
                    logger.warning(f"⚠️ Serwer SMTP zwrócił błędy dla niektórych odbiorców: {result}")
                    return False
            
            logger.info(f"✅ Email wysłany: '{subject}' do {recipient}")
            return True
            
        except smtplib.SMTPAuthenticationError:
            logger.error("❌ Błąd uwierzytelniania SMTP - sprawdź dane logowania")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"❌ Błąd SMTP: {e}")
            return False
        except Exception as e:
            logger.error(f"❌ Nieoczekiwany błąd podczas wysyłania emaila: {e}")
            return False
    
    def _create_alert_html(self, alert_type: str, message: str, device_info: Optional[dict]) -> str:
        """
        Stwórz HTML dla alertu używając template
        
        Args:
            alert_type: Typ alertu
            message: Treść alertu
            device_info: Informacje o urządzeniu
            
        Returns:
            str: HTML wiadomości
        """
        from flask import render_template
        
        # Emoji dla różnych typów alertów
        emoji_map = {
            'new_device': '🆕',
            'suspicious_traffic': '⚠️',
            'arp_spoofing': '🛡️',
            'mac_duplicate': '🔒',
        }
        
        alert_emoji = emoji_map.get(alert_type, '🔔')
        
        # Renderuj template
        html = render_template('emails/alert_simple.html',
                             alert_emoji=alert_emoji,
                             message=message,
                             device_info=device_info,
                             timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        return html
    
    def send_alert_to_recipients(self, alert_type: str, message: str, device_info: Optional[dict] = None) -> dict:
        """
        Wyślij alert do wszystkich aktywnych odbiorców zainteresowanych danym typem alertu
        
        Args:
            alert_type: Typ alertu
            message: Treść alertu
            device_info: Informacje o urządzeniu
            
        Returns:
            dict: Statystyki wysyłki (success_count, failed_count, recipients)
        """
        from app.models import EmailRecipient
        
        if not self.enabled:
            logger.warning("⚠️ Email manager wyłączony - pomijam wysyłkę alertów")
            return {'success_count': 0, 'failed_count': 0, 'recipients': []}
        
        # Pobierz aktywnych odbiorców zainteresowanych tym typem alertu
        recipients = EmailRecipient.query.filter_by(is_active=True).all()
        interested_recipients = [r for r in recipients if r.should_notify(alert_type)]
        
        # Fallback: jeśli brak odbiorców w bazie, użyj ALERT_EMAIL z konfiguracji
        if not interested_recipients:
            if self.config.ALERT_EMAIL:
                logger.info(f"ℹ️ Brak odbiorców w bazie - używam ALERT_EMAIL: {self.config.ALERT_EMAIL}")
                # Utwórz tymczasowy obiekt odbiorcy
                class FallbackRecipient:
                    def __init__(self, email):
                        self.email = email
                interested_recipients = [FallbackRecipient(self.config.ALERT_EMAIL)]
            else:
                logger.warning(f"⚠️ Brak odbiorców zainteresowanych alertem typu: {alert_type}")
                return {'success_count': 0, 'failed_count': 0, 'recipients': []}
        
        # Mapowanie typów alertów na tematy
        subject_map = {
            'new_device': '🆕 Nowe urządzenie w sieci',
            'suspicious_traffic': '⚠️ Podejrzany ruch sieciowy',
            'arp_spoofing': '🛡️ ALERT: ARP Spoofing',
            'mac_duplicate': '🔒 ALERT: Duplikat MAC',
        }
        
        subject = subject_map.get(alert_type, '🔔 Alert z LAN Monitor')
        html_body = self._create_alert_html(alert_type, message, device_info)
        
        success_count = 0
        failed_count = 0
        sent_to = []
        
        for recipient in interested_recipients:
            success = self.send_email(subject, html_body, to_email=recipient.email, html=True)
            if success:
                success_count += 1
                sent_to.append(recipient.email)
                logger.info(f"✅ Alert wysłany do: {recipient.email}")
            else:
                failed_count += 1
                logger.error(f"❌ Nie udało się wysłać alertu do: {recipient.email}")
        
        logger.info(f"📊 Statystyki wysyłki alertu '{alert_type}': {success_count} sukces, {failed_count} błędów")
        
        return {
            'success_count': success_count,
            'failed_count': failed_count,
            'recipients': sent_to
        }
