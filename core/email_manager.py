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
    
    def send_email(self, subject: str, body: str, to_email: Optional[str] = None, html: bool = False) -> bool:
        """
        Wyślij email
        
        Args:
            subject: Temat wiadomości
            body: Treść wiadomości
            to_email: Adres odbiorcy (opcjonalnie, domyślnie ALERT_EMAIL)
            html: Czy treść jest w formacie HTML
            
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
            msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')
            
            # Dodaj treść
            if html:
                msg.attach(MIMEText(body, 'html', 'utf-8'))
            else:
                msg.attach(MIMEText(body, 'plain', 'utf-8'))
            
            # Połącz się z serwerem SMTP
            with smtplib.SMTP(self.config.MAIL_SERVER, self.config.MAIL_PORT) as server:
                if self.config.MAIL_USE_TLS:
                    server.starttls()
                
                server.login(self.config.MAIL_USERNAME, self.config.MAIL_PASSWORD)
                server.send_message(msg)
            
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
    
    def send_alert_email(self, alert_type: str, message: str, device_info: Optional[dict] = None) -> bool:
        """
        Wyślij email o alercie
        
        Args:
            alert_type: Typ alertu (new_device, device_offline, unusual_traffic, itp.)
            message: Treść alertu
            device_info: Dodatkowe informacje o urządzeniu (opcjonalne)
            
        Returns:
            bool: True jeśli wysłano pomyślnie
        """
        # Mapowanie typów alertów na tematy
        subject_map = {
            'new_device': '🆕 Nowe urządzenie w sieci',
            'device_offline': '⚠️ Urządzenie offline',
            'device_online': '✅ Urządzenie ponownie online',
            'unusual_traffic': '📊 Nietypowy ruch sieciowy',
            'high_traffic': '🔥 Wysoki ruch sieciowy',
        }
        
        subject = subject_map.get(alert_type, '🔔 Alert z LAN Monitor')
        
        # Przygotuj treść HTML
        html_body = self._create_alert_html(alert_type, message, device_info)
        
        # Przygotuj treść tekstową (fallback)
        text_body = self._create_alert_text(alert_type, message, device_info)
        
        # Wyślij email z treścią HTML
        return self.send_email(subject, html_body, html=True)
    
    def _create_alert_html(self, alert_type: str, message: str, device_info: Optional[dict]) -> str:
        """
        Stwórz HTML dla alertu
        
        Args:
            alert_type: Typ alertu
            message: Treść alertu
            device_info: Informacje o urządzeniu
            
        Returns:
            str: HTML wiadomości
        """
        # Emoji dla różnych typów alertów
        emoji_map = {
            'new_device': '🆕',
            'device_offline': '⚠️',
            'device_online': '✅',
            'unusual_traffic': '📊',
            'high_traffic': '🔥',
        }
        
        emoji = emoji_map.get(alert_type, '🔔')
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    border-radius: 10px 10px 0 0;
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 24px;
                }}
                .content {{
                    background: white;
                    padding: 30px;
                    border: 1px solid #e2e8f0;
                    border-top: none;
                    border-radius: 0 0 10px 10px;
                }}
                .alert-box {{
                    background: #f7fafc;
                    border-left: 4px solid #667eea;
                    padding: 20px;
                    margin: 20px 0;
                    border-radius: 5px;
                }}
                .device-info {{
                    background: #fff;
                    border: 1px solid #e2e8f0;
                    border-radius: 8px;
                    padding: 15px;
                    margin: 15px 0;
                }}
                .device-info table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                .device-info td {{
                    padding: 8px;
                    border-bottom: 1px solid #f1f5f9;
                }}
                .device-info td:first-child {{
                    font-weight: 600;
                    color: #64748b;
                    width: 120px;
                }}
                .footer {{
                    text-align: center;
                    padding: 20px;
                    color: #64748b;
                    font-size: 14px;
                }}
                .timestamp {{
                    color: #94a3b8;
                    font-size: 14px;
                    margin-top: 15px;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{emoji} LAN Monitor Alert</h1>
            </div>
            <div class="content">
                <div class="alert-box">
                    <p style="margin: 0; font-size: 16px;"><strong>{message}</strong></p>
                </div>
        """
        
        # Dodaj informacje o urządzeniu jeśli są dostępne
        if device_info:
            html += """
                <div class="device-info">
                    <h3 style="margin-top: 0; color: #1e293b;">Informacje o urządzeniu:</h3>
                    <table>
            """
            
            if device_info.get('ip_address'):
                html += f"""
                        <tr>
                            <td>Adres IP:</td>
                            <td><strong>{device_info['ip_address']}</strong></td>
                        </tr>
                """
            
            if device_info.get('mac_address'):
                html += f"""
                        <tr>
                            <td>Adres MAC:</td>
                            <td><code>{device_info['mac_address']}</code></td>
                        </tr>
                """
            
            if device_info.get('hostname'):
                html += f"""
                        <tr>
                            <td>Nazwa:</td>
                            <td>{device_info['hostname']}</td>
                        </tr>
                """
            
            if device_info.get('vendor'):
                html += f"""
                        <tr>
                            <td>Producent:</td>
                            <td>{device_info['vendor']}</td>
                        </tr>
                """
            
            if device_info.get('first_seen'):
                html += f"""
                        <tr>
                            <td>Pierwsze pojawienie:</td>
                            <td>{device_info['first_seen']}</td>
                        </tr>
                """
            
            html += """
                    </table>
                </div>
            """
        
        html += f"""
                <div class="timestamp">
                    <p>Czas alertu: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </div>
            <div class="footer">
                <p>To jest automatyczna wiadomość z systemu LAN Monitor</p>
                <p style="font-size: 12px; color: #94a3b8;">Aby zmienić ustawienia powiadomień, zaloguj się do panelu administracyjnego</p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _create_alert_text(self, alert_type: str, message: str, device_info: Optional[dict]) -> str:
        """
        Stwórz tekstową wersję alertu (fallback dla klientów bez HTML)
        
        Args:
            alert_type: Typ alertu
            message: Treść alertu
            device_info: Informacje o urządzeniu
            
        Returns:
            str: Tekstowa wersja wiadomości
        """
        text = f"""
LAN MONITOR - ALERT

{message}

"""
        
        if device_info:
            text += "INFORMACJE O URZĄDZENIU:\n"
            text += "-" * 40 + "\n"
            
            if device_info.get('ip_address'):
                text += f"Adres IP:      {device_info['ip_address']}\n"
            if device_info.get('mac_address'):
                text += f"Adres MAC:     {device_info['mac_address']}\n"
            if device_info.get('hostname'):
                text += f"Nazwa:         {device_info['hostname']}\n"
            if device_info.get('vendor'):
                text += f"Producent:     {device_info['vendor']}\n"
            if device_info.get('first_seen'):
                text += f"Pierwsze pojawienie: {device_info['first_seen']}\n"
            
            text += "-" * 40 + "\n\n"
        
        text += f"Czas alertu: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        text += "---\n"
        text += "To jest automatyczna wiadomość z systemu LAN Monitor\n"
        
        return text
    
    def test_connection(self) -> bool:
        """
        Przetestuj połączenie SMTP
        
        Returns:
            bool: True jeśli połączenie działa
        """
        if not self.enabled:
            logger.error("❌ Email manager jest wyłączony")
            return False
        
        try:
            with smtplib.SMTP(self.config.MAIL_SERVER, self.config.MAIL_PORT, timeout=10) as server:
                if self.config.MAIL_USE_TLS:
                    server.starttls()
                server.login(self.config.MAIL_USERNAME, self.config.MAIL_PASSWORD)
            
            logger.info("✅ Połączenie SMTP działa poprawnie")
            return True
            
        except Exception as e:
            logger.error(f"❌ Test połączenia SMTP nieudany: {e}")
            return False
    
    def send_welcome_email(self, recipient_email: str, recipient_name: Optional[str] = None) -> bool:
        """
        Wyślij email powitalny do nowego odbiorcy
        
        Args:
            recipient_email: Adres email odbiorcy
            recipient_name: Nazwa odbiorcy (opcjonalne)
            
        Returns:
            bool: True jeśli wysłano pomyślnie
        """
        if not self.enabled:
            logger.warning("Email manager wyłączony - nie wysyłam emaila powitalnego")
            return False
        
        subject = "Witaj w systemie powiadomien LAN Monitor"
        
        name_display = recipient_name if recipient_name else recipient_email
        
        # Prosta wersja tekstowa zamiast HTML
        text_body = f"""Witaj, {name_display}!

Twoj adres email zostal pomyslnie dodany do systemu powiadomien LAN Monitor.

Od teraz bedziesz otrzymywac powiadomienia o zdarzeniach w Twojej sieci lokalnej zgodnie z wybranymi preferencjami.

O czym mozesz byc powiadamiany:
- Nowe urzadzenia - gdy nowe urzadzenie pojawi sie w sieci
- Urzadzenie offline - gdy urzadzenie przestanie byc dostepne
- Urzadzenie online - gdy urzadzenie ponownie sie polaczy
- Nietypowy ruch - wykrycie nietypowej aktywnosci sieciowej
- Wysoki ruch - przekroczenie limitow transferu danych

Mozesz w kazdej chwili zmienic swoje preferencje powiadomien w panelu administracyjnym systemu LAN Monitor, w sekcji Ustawienia email.

---
To jest automatyczna wiadomosc z systemu LAN Monitor
Data rejestracji: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        logger.info(f"Wysyłam email powitalny do: {recipient_email}")
        success = self.send_email(subject, text_body, to_email=recipient_email, html=False)
        
        if success:
            logger.info(f"✅ Email powitalny wysłany pomyślnie do: {recipient_email}")
        else:
            logger.error(f"❌ Nie udało się wysłać emaila powitalnego do: {recipient_email}")
        
        return success
    
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
            'device_offline': '⚠️ Urządzenie offline',
            'device_online': '✅ Urządzenie ponownie online',
            'unusual_traffic': '📊 Nietypowy ruch sieciowy',
            'high_traffic': '🔥 Wysoki ruch sieciowy',
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
