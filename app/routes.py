"""
Blueprint głównych stron - dashboard, strona główna, szczegóły urządzenia
"""
from flask import Blueprint, render_template, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from app.models import Device, DeviceActivity, Alert
from app.helpers import format_bytes
from app import db
from sqlalchemy import desc
from datetime import datetime
import threading
import logging

logger = logging.getLogger(__name__)

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    """Strona główna - przekierowanie do dashboardu lub logowania"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))


@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Dashboard z listą AKTYWNYCH urządzeń w sieci"""
    from core.traffic_manager import traffic_manager
    
    # Pobierz tylko AKTYWNE urządzenia
    devices = Device.query.filter_by(is_online=True).order_by(desc(Device.last_seen)).all()
    
    # Statystyki
    total_devices = Device.query.count()
    online_devices = Device.query.filter_by(is_online=True).count()
    new_devices = Device.query.filter_by(is_new=True).count()
    
    # Ostatnie alerty
    recent_alerts = Alert.query.filter_by(is_read=False).order_by(desc(Alert.created_at)).limit(5).all()
    
    # Pobierz całkowite statystyki ruchu
    total_stats = traffic_manager.get_total_stats()
    
    return render_template('dashboard.html',
                         devices=devices,
                         total_devices=total_devices,
                         online_devices=online_devices,
                         new_devices=new_devices,
                         recent_alerts=recent_alerts,
                         total_stats=total_stats)


@main_bp.route('/devices/all')
@login_required
def all_devices():
    """Strona ze wszystkimi urządzeniami (aktywne i nieaktywne)"""
    # Pobierz wszystkie urządzenia pogrupowane
    active_devices = Device.query.filter_by(is_online=True).order_by(desc(Device.last_seen)).all()
    inactive_devices = Device.query.filter_by(is_online=False).order_by(desc(Device.last_seen)).all()
    
    # Statystyki
    total_devices = Device.query.count()
    online_devices = len(active_devices)
    offline_devices = len(inactive_devices)
    
    return render_template('all_devices.html',
                         active_devices=active_devices,
                         inactive_devices=inactive_devices,
                         total_devices=total_devices,
                         online_devices=online_devices,
                         offline_devices=offline_devices)


@main_bp.route('/alerts')
@main_bp.route('/alerts/<period>')
@login_required
def alerts_page(period='1'):
    """
    Strona z alertami
    period: 'all'=wszystkie, '1'=ostatnia godzina, '24'=ostatnie 24h, '168'=tydzień (7*24h)
    """
    from datetime import datetime, timedelta
    
    query = Alert.query
    
    # Konwertuj period na int jeśli nie jest 'all'
    if period == 'all':
        period_int = -1
    else:
        try:
            period_int = int(period)
        except ValueError:
            period_int = 1
    
    if period_int > 0:
        # Filtruj według czasu
        time_threshold = datetime.now() - timedelta(hours=period_int)
        query = query.filter(Alert.created_at >= time_threshold)
    
    # Pobierz alerty
    alerts = query.order_by(desc(Alert.created_at)).all()
    
    # Zlicz nieprzeczytane
    unread_count = Alert.query.filter_by(is_read=False).count()
    
    # Mapowanie okresów na nazwy
    period_names = {
        '1': 'Ostatnia godzina',
        '24': 'Ostatnie 24 godziny',
        '168': 'Ostatni tydzień',
        'all': 'Wszystkie alerty'
    }
    
    period_name = period_names.get(period, 'Wszystkie alerty')
    
    return render_template('alerts.html',
                         alerts=alerts,
                         unread_count=unread_count,
                         period=period,
                         period_name=period_name)


@main_bp.route('/alerts/<int:alert_id>/mark-read', methods=['POST'])
@login_required
def mark_alert_read(alert_id):
    """Oznacz alert jako przeczytany"""
    alert = Alert.query.get_or_404(alert_id)
    alert.is_read = True
    db.session.commit()
    return jsonify({'status': 'success'})


@main_bp.route('/settings/email')
@login_required
def email_settings():
    """Strona ustawień powiadomień email i zarządzania odbiorcami"""
    from core.email_manager import EmailManager
    from config import Config
    from app.models import EmailRecipient
    
    email_manager = EmailManager(Config)
    
    # Pobierz konfigurację
    config_status = {
        'enabled': email_manager.enabled,
        'server': Config.MAIL_SERVER,
        'port': Config.MAIL_PORT,
        'username': Config.MAIL_USERNAME,
        'alert_email': Config.ALERT_EMAIL,
        'use_tls': Config.MAIL_USE_TLS
    }
    
    # Pobierz listę odbiorców
    recipients = EmailRecipient.query.order_by(EmailRecipient.created_at.desc()).all()
    
    return render_template('email_settings.html',
                         config=config_status,
                         recipients=recipients)


@main_bp.route('/settings/email/test', methods=['POST'])
@login_required
def test_email():
    """Testuj połączenie email"""
    from core.email_manager import EmailManager
    from config import Config
    
    email_manager = EmailManager(Config)
    
    # Test połączenia
    if email_manager.test_connection():
        # Wyślij testową wiadomość
        success = email_manager.send_email(
            subject='🧪 Test powiadomień LAN Monitor',
            body='To jest testowa wiadomość z systemu LAN Monitor. Jeśli widzisz tę wiadomość, konfiguracja email działa poprawnie!',
            html=False
        )
        
        if success:
            flash('Test email zakończony sukcesem! Sprawdź swoją skrzynkę pocztową.', 'success')
        else:
            flash('Połączenie działa, ale nie udało się wysłać wiadomości.', 'warning')
    else:
        flash('Test połączenia email nieudany. Sprawdź konfigurację SMTP.', 'error')
    
    return redirect(url_for('main.email_settings'))


@main_bp.route('/device/<int:device_id>')
@login_required
def device_detail(device_id):
    """Szczegóły urządzenia - ruch sieciowy, statystyki (z Dashboard)"""
    from datetime import datetime, timedelta
    from flask import current_app, request
    from core.traffic_manager import traffic_manager
    
    device = Device.query.get_or_404(device_id)
    
    # Zawsze powrót do Dashboard
    back_url = url_for('main.dashboard')
    back_text = 'Dashboard'
    
    logger.info(f"📱 Wyświetlanie szczegółów urządzenia: {device.ip_address}")
    
    # Pobierz aktywność z ostatnich 24h
    activities = DeviceActivity.query.filter_by(device_id=device_id)\
        .order_by(desc(DeviceActivity.timestamp))\
        .limit(100)\
        .all()
    
    logger.info(f"📊 Znaleziono {len(activities)} rekordów aktywności dla urządzenia {device.ip_address}")
    
    # Pobierz bieżące prędkości (KB/s)
    download_rate = "0.00 KB/s"
    upload_rate = "0.00 KB/s"
    
    logger.debug(f"🔍 traffic_manager: {traffic_manager}")
    logger.debug(f"🔍 traffic_monitor: {traffic_manager.traffic_monitor if traffic_manager else 'None'}")
    logger.debug(f"🔍 monitor running: {traffic_manager.traffic_monitor.running if traffic_manager and traffic_manager.traffic_monitor else 'None'}")
    
    # Najpierw sprawdź czy traffic_monitor działa i jest zainicjalizowany
    if traffic_manager and traffic_manager.traffic_monitor and traffic_manager.traffic_monitor.running:
        try:
            logger.info(f"✅ Traffic monitor działa - pobieranie rates...")
            rates = traffic_manager.traffic_monitor.get_current_rates()
            logger.info(f"📊 Otrzymano rates dla {len(rates)} urządzeń: {list(rates.keys())}")
            
            device_rate = rates.get(device.ip_address, (0, 0))
            
            logger.info(f"📈 Rates dla {device.ip_address}: ↓{device_rate[0]:.2f} KB/s ↑{device_rate[1]:.2f} KB/s")
            
            # Jeśli mamy aktywny ruch w ostatnich 5s
            if device_rate[0] > 0 or device_rate[1] > 0:
                download_rate = f"{device_rate[0]:.2f} KB/s"
                upload_rate = f"{device_rate[1]:.2f} KB/s"
                logger.info(f"✅ Używam aktywnych rates")
            # Jeśli brak aktywnego ruchu, spróbuj obliczyć z ostatniej aktywności
            elif activities:
                latest = activities[0]
                # Oblicz średnią prędkość z ostatniego okresu aktualizacji (60s)
                update_interval = current_app.config.get('TRAFFIC_UPDATE_INTERVAL', 60)
                if latest.bytes_received > 0 or latest.bytes_sent > 0:
                    download_rate = f"{(latest.bytes_received / 1024 / update_interval):.2f} KB/s"
                    upload_rate = f"{(latest.bytes_sent / 1024 / update_interval):.2f} KB/s"
                    logger.info(f"✅ Używam ostatniej aktywności: ↓{latest.bytes_received} B ↑{latest.bytes_sent} B")
        except Exception as e:
            logger.error(f"❌ Błąd pobierania rates: {e}", exc_info=True)
            # Fallback do ostatniej aktywności
            if activities:
                latest = activities[0]
                update_interval = current_app.config.get('TRAFFIC_UPDATE_INTERVAL', 60)
                download_rate = f"{(latest.bytes_received / 1024 / update_interval):.2f} KB/s"
                upload_rate = f"{(latest.bytes_sent / 1024 / update_interval):.2f} KB/s"
    elif activities:
        # Traffic monitor nie działa, użyj danych z ostatniej aktywności
        logger.warning(f"⚠ Traffic monitor nie działa, używam danych z ostatniej aktywności")
        latest = activities[0]
        update_interval = current_app.config.get('TRAFFIC_UPDATE_INTERVAL', 60)
        download_rate = f"{(latest.bytes_received / 1024 / update_interval):.2f} KB/s"
        upload_rate = f"{(latest.bytes_sent / 1024 / update_interval):.2f} KB/s"
        logger.info(f"📊 Ostatnia aktywność: ↓{latest.bytes_received} B ↑{latest.bytes_sent} B z {latest.timestamp}")
    else:
        logger.warning(f"⚠ Brak danych ruchu dla urządzenia {device.ip_address}")    # Oblicz całkowity ruch z ostatnich 24h
    total_bytes_in = sum(a.bytes_received for a in activities)
    total_bytes_out = sum(a.bytes_sent for a in activities)
    total_bytes = total_bytes_in + total_bytes_out
    total_traffic = format_bytes(total_bytes)
    
    # Ostatnia aktywność
    if device.last_seen:
        last_seen = device.last_seen.strftime('%Y-%m-%d %H:%M:%S')
    else:
        last_seen = "Nigdy"
    
    # Konfiguracja Grafana
    grafana_enabled = current_app.config.get('GRAFANA_ENABLED', False)
    grafana_url = current_app.config.get('GRAFANA_URL', 'http://localhost:3000')
    dashboard_uid = current_app.config.get('GRAFANA_DASHBOARD_UID', 'device-traffic')
    
    return render_template('device_detail.html',
                         device=device,
                         activities=activities,
                         download_rate=download_rate,
                         upload_rate=upload_rate,
                         total_traffic=total_traffic,
                         last_seen=last_seen,
                         grafana_enabled=grafana_enabled,
                         grafana_url=grafana_url,
                         dashboard_uid=dashboard_uid,
                         back_url=back_url,
                         back_text=back_text)


@main_bp.route('/device/<int:device_id>/all')
@login_required
def device_detail_all(device_id):
    """Szczegóły urządzenia z widoku 'Wszystkie urządzenia' - tylko raporty"""
    from app.models import DeviceReport, EmailRecipient
    
    device = Device.query.get_or_404(device_id)
    
    # Pobierz ostatnie 10 raportów
    reports = DeviceReport.query.filter_by(device_id=device.id)\
        .order_by(DeviceReport.generated_at.desc())\
        .limit(10)\
        .all()
    
    # Pobierz listę odbiorców email
    email_recipients = EmailRecipient.query.filter_by(is_active=True).all()
    
    return render_template('device_detail_all.html',
                         device=device,
                         reports=reports,
                         email_recipients=email_recipients)


@main_bp.route('/mark-alerts-read', methods=['POST'])
@login_required
def mark_alerts_read():
    """Oznacz wszystkie nieprzeczytane alerty jako przeczytane"""
    try:
        # Znajdź wszystkie nieprzeczytane alerty
        unread_alerts = Alert.query.filter_by(is_read=False).all()
        
        # Oznacz jako przeczytane
        for alert in unread_alerts:
            alert.is_read = True
        
        db.session.commit()
        
        logger.info(f"✅ Oznaczono {len(unread_alerts)} alertów jako przeczytane")
        
        return jsonify({
            'success': True,
            'marked_count': len(unread_alerts)
        })
    except Exception as e:
        logger.error(f"❌ Błąd oznaczania alertów: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@main_bp.route('/scan-network')
@login_required
def scan_network():
    """Uruchom skanowanie sieci w tle"""
    def run_scan_task():
        """Zadanie skanowania w tle"""
        from app import create_app
        from core.network_scanner import NetworkScanner
        
        app = create_app()
        with app.app_context():
            try:
                scanner = NetworkScanner()
                # Automatyczne wykrycie zakresu sieci
                network_range = scanner.get_network_interface_range()
                scanner.network_range = network_range
                
                # Wykonaj skanowanie
                devices = scanner.scan_network()
                
                # Aktualizuj bazę danych
                if devices:
                    scanner.update_database(devices)
            except Exception as e:
                print(f"❌ Błąd podczas skanowania: {e}")
    
    # Uruchom skanowanie w osobnym wątku
    thread = threading.Thread(target=run_scan_task)
    thread.daemon = True
    thread.start()
    
    flash('Skanowanie sieci zostało uruchomione w tle. Odśwież stronę za chwilę.', 'info')
    return redirect(url_for('main.dashboard'))


@main_bp.route('/api/device/<int:device_id>/stats')
@login_required
def device_stats_api(device_id):
    """API endpoint zwracający aktualne statystyki urządzenia (dla real-time update)"""
    from flask import jsonify
    from core.traffic_manager import traffic_manager
    
    import logging
    logger = logging.getLogger(__name__)
    
    device = Device.query.get_or_404(device_id)
    
    # Pobierz bieżące prędkości (KB/s) z traffic monitor
    rates = traffic_manager.traffic_monitor.get_current_rates()
    device_rate = rates.get(device.ip_address, (0, 0))
    
    # Debug logging
    logger.debug(f"API call for device {device.ip_address}")
    logger.debug(f"All rates: {list(rates.keys())}")
    logger.debug(f"Device rate: {device_rate}")
    
    # Pobierz najnowszą aktywność z bazy
    latest_activity = DeviceActivity.query.filter_by(device_id=device_id)\
        .order_by(desc(DeviceActivity.timestamp))\
        .first()
    
    # Przygotuj dane do zwrócenia
    download_kbps = device_rate[0]  # download
    upload_kbps = device_rate[1]    # upload
    
    response = {
        'download_rate': download_kbps,
        'upload_rate': upload_kbps,
        'download_rate_formatted': f"{download_kbps:.2f} KB/s",
        'upload_rate_formatted': f"{upload_kbps:.2f} KB/s",
        'last_seen': device.last_seen.strftime('%Y-%m-%d %H:%M:%S') if device.last_seen else 'Nigdy',
        'status': 'online' if device.is_online else 'offline',
        'latest_activity': None
    }
    
    if latest_activity:
        response['latest_activity'] = {
            'timestamp': latest_activity.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'bytes_received': latest_activity.bytes_received,
            'bytes_sent': latest_activity.bytes_sent,
            'packets_received': latest_activity.packets_received,
            'packets_sent': latest_activity.packets_sent
        }
    
    return jsonify(response)


@main_bp.route('/settings/email/recipients/add', methods=['POST'])
@login_required
def add_email_recipient():
    """Dodaj nowego odbiorcę powiadomień email"""
    from flask import request
    from app.models import EmailRecipient
    from core.email_manager import EmailManager
    from config import Config
    
    try:
        email = request.form.get('email', '').strip()
        name = request.form.get('name', '').strip() or None
        
        # Walidacja
        if not email:
            flash('Adres email jest wymagany!', 'error')
            return redirect(url_for('main.email_settings'))
        
        # Sprawdź czy już istnieje
        existing = EmailRecipient.query.filter_by(email=email).first()
        if existing:
            flash(f'Odbiorca {email} już istnieje w bazie!', 'warning')
            return redirect(url_for('main.email_settings'))
        
        # Pobierz preferencje powiadomień
        notify_new_device = request.form.get('notify_new_device') == 'on'
        notify_device_offline = request.form.get('notify_device_offline') == 'on'
        notify_device_online = request.form.get('notify_device_online') == 'on'
        notify_unusual_traffic = request.form.get('notify_unusual_traffic') == 'on'
        notify_high_traffic = request.form.get('notify_high_traffic') == 'on'
        
        # Utwórz nowego odbiorcę
        recipient = EmailRecipient(
            email=email,
            name=name,
            notify_new_device=notify_new_device,
            notify_device_offline=notify_device_offline,
            notify_device_online=notify_device_online,
            notify_unusual_traffic=notify_unusual_traffic,
            notify_high_traffic=notify_high_traffic
        )
        
        db.session.add(recipient)
        db.session.commit()
        
        # Wyślij email powitalny
        email_manager = EmailManager(Config)
        
        if email_manager.enabled:
            try:
                html_body = render_template('emails/welcome_simple.html',
                                          recipient_name=name if name else None,
                                          recipient_email=email,
                                          current_date=datetime.now().strftime('%d.%m.%Y %H:%M'),
                                          notify_new_device=notify_new_device,
                                          notify_device_offline=notify_device_offline,
                                          notify_device_online=notify_device_online,
                                          notify_unusual_traffic=notify_unusual_traffic,
                                          notify_high_traffic=notify_high_traffic)
                
                subject = "Witaj w systemie LAN Monitor!"
                welcome_sent = email_manager.send_email(subject, html_body, to_email=email, html=True)
                
                if welcome_sent:
                    flash(f'✅ Dodano odbiorcę {email} i wysłano email powitalny!', 'success')
                else:
                    flash(f'✅ Dodano odbiorcę {email}, ale nie udało się wysłać emaila powitalnego.', 'warning')
            except Exception as email_error:
                logger.error(f"Błąd wysyłania emaila powitalnego: {email_error}")
                flash(f'✅ Dodano odbiorcę {email}, ale wystąpił błąd przy wysyłaniu emaila: {str(email_error)}', 'warning')
        else:
            flash(f'✅ Dodano odbiorcę {email} (email manager wyłączony).', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Błąd dodawania odbiorcy: {e}")
        flash(f'Błąd podczas dodawania odbiorcy: {str(e)}', 'error')
    
    return redirect(url_for('main.email_settings'))


@main_bp.route('/settings/email/recipients/<int:recipient_id>/edit', methods=['POST'])
@login_required
def edit_email_recipient(recipient_id):
    """Edytuj preferencje odbiorcy"""
    from flask import request
    from app.models import EmailRecipient
    
    try:
        recipient = EmailRecipient.query.get_or_404(recipient_id)
        
        # Aktualizuj nazwę
        recipient.name = request.form.get('name', '').strip() or None
        
        # Aktualizuj preferencje
        recipient.notify_new_device = request.form.get('notify_new_device') == 'on'
        recipient.notify_device_offline = request.form.get('notify_device_offline') == 'on'
        recipient.notify_device_online = request.form.get('notify_device_online') == 'on'
        recipient.notify_unusual_traffic = request.form.get('notify_unusual_traffic') == 'on'
        recipient.notify_high_traffic = request.form.get('notify_high_traffic') == 'on'
        
        db.session.commit()
        flash(f'✅ Zaktualizowano preferencje dla {recipient.email}', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Błąd edycji odbiorcy: {e}")
        flash(f'Błąd podczas edycji odbiorcy: {str(e)}', 'error')
    
    return redirect(url_for('main.email_settings'))


@main_bp.route('/settings/email/recipients/<int:recipient_id>/toggle', methods=['POST'])
@login_required
def toggle_email_recipient(recipient_id):
    """Aktywuj/dezaktywuj odbiorcę"""
    from app.models import EmailRecipient
    
    try:
        recipient = EmailRecipient.query.get_or_404(recipient_id)
        recipient.is_active = not recipient.is_active
        db.session.commit()
        
        status = 'aktywowany' if recipient.is_active else 'dezaktywowany'
        flash(f'✅ Odbiorca {recipient.email} został {status}', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Błąd przełączania odbiorcy: {e}")
        flash(f'Błąd: {str(e)}', 'error')
    
    return redirect(url_for('main.email_settings'))


@main_bp.route('/settings/email/recipients/<int:recipient_id>/delete', methods=['POST'])
@login_required
def delete_email_recipient(recipient_id):
    """Usuń odbiorcę"""
    from app.models import EmailRecipient
    
    try:
        recipient = EmailRecipient.query.get_or_404(recipient_id)
        email = recipient.email
        db.session.delete(recipient)
        db.session.commit()
        
        flash(f'✅ Usunięto odbiorcę {email}', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Błąd usuwania odbiorcy: {e}")
        flash(f'Błąd: {str(e)}', 'error')
    
    return redirect(url_for('main.email_settings'))


@main_bp.route('/device/<int:device_id>/generate-report', methods=['POST'])
@login_required
def generate_report(device_id):
    """Generuj nowy raport i zapisz w historii (opcjonalnie wyślij emailem)"""
    from datetime import datetime
    from flask import request, jsonify
    
    logger.info(f"🔵 generate_report wywołane dla device_id={device_id}")
    
    try:
        # Pobierz parametry
        period_days = int(request.args.get('period', 7))
        format_type = request.args.get('format', 'html')
        email = request.args.get('email', '')
        
        logger.info(f"📊 Parametry: period={period_days}, format={format_type}, email={email}")
        
        device = Device.query.get_or_404(device_id)
        
        logger.info(f"🖥️ Urządzenie: {device.hostname or device.ip_address}")
        
        # Zapisz w historii raportów
        from app.models import DeviceReport
        report_record = DeviceReport(
            device_id=device.id,
            period_days=period_days
        )
        db.session.add(report_record)
        db.session.commit()
        
        # Jeśli wybrano wysyłkę emailem
        if email:
            # Generuj PDF
            from datetime import timedelta
            from io import BytesIO
            from weasyprint import HTML
            
            start_date = datetime.now() - timedelta(days=period_days)
            activities = DeviceActivity.query.filter(
                DeviceActivity.device_id == device.id,
                DeviceActivity.timestamp >= start_date
            ).order_by(DeviceActivity.timestamp.desc()).all()
            
            logger.info(f"📈 Pobrano {len(activities)} aktywności")
            
            stats = calculate_device_stats(device, activities, period_days)
            logger.info(f"📊 Obliczono statystyki: {stats}")
            
            # Renderuj HTML raportu
            logger.info("🎨 Renderuję HTML raportu...")
            html_content = render_template('device_report.html',
                                         device=device,
                                         activities=activities,
                                         stats=stats,
                                         period_days=period_days,
                                         start_date=start_date,
                                         generated_at=datetime.now())
            
            logger.info("📄 Generuję PDF...")
            # Generuj PDF
            pdf_data = HTML(string=html_content, base_url=request.url_root).write_pdf()
            logger.info(f"✅ PDF wygenerowany, rozmiar: {len(pdf_data)} bajtów")
            
            # Wyślij email
            from core.email_manager import EmailManager
            from config import Config
            logger.info("📧 Inicjalizuję EmailManager...")
            email_manager = EmailManager(Config)
            
            period_name = {1: "dzienny", 7: "tygodniowy", 30: "miesięczny"}.get(period_days, f"{period_days}-dniowy")
            subject = f"Raport {period_name} - {device.hostname or device.ip_address}"
            
            # Przygotuj dane do szablonu emaila
            email_stats = {
                'total_download': format_bytes(stats.get('total_traffic_in_raw', 0)) if stats else '0 B',
                'total_upload': format_bytes(stats.get('total_traffic_out_raw', 0)) if stats else '0 B',
                'total_traffic': format_bytes(stats.get('total_traffic_raw', 0)) if stats else '0 B',
                'active_sessions': stats.get('total_records', 0) if stats else 0
            }
            
            # Renderuj email z uproszczonego template
            email_body = render_template('emails/report_simple.html',
                                        device_name=device.hostname or 'Nieznane',
                                        device_ip=device.ip_address,
                                        period_name=period_name,
                                        period_days=period_days,
                                        generated_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                        stats=email_stats)
            
            filename = f"raport_{device.hostname or device.ip_address}_{period_days}d_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            
            try:
                result = email_manager.send_email(
                    subject=subject,
                    body=email_body,
                    to_email=email,
                    html=True,
                    attachment=pdf_data,
                    attachment_name=filename
                )
                if result:
                    return jsonify({'success': True, 'report_id': report_record.id, 'email_sent': True})
                else:
                    return jsonify({'success': True, 'report_id': report_record.id, 'email_sent': False, 'email_error': 'Nie udało się wysłać emaila'})
            except Exception as email_error:
                logger.error(f"Błąd wysyłania emaila: {email_error}")
                return jsonify({'success': True, 'report_id': report_record.id, 'email_sent': False, 'email_error': str(email_error)})
        
        return jsonify({'success': True, 'report_id': report_record.id, 'email_sent': False})
        
    except Exception as e:
        import traceback
        logger.error(f"❌ Błąd generowania raportu: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)}), 500


@main_bp.route('/device/<int:device_id>/report')
@login_required
def device_report(device_id):
    """Wyświetl raport HTML dla urządzenia (bez zapisywania do historii)"""
    from datetime import datetime, timedelta
    from sqlalchemy import func
    from flask import request
    
    # Pobierz urządzenie
    device = Device.query.get_or_404(device_id)
    
    # Pobierz okres z parametru (domyślnie 7 dni)
    period_days = int(request.args.get('period', 7))
    start_date = datetime.now() - timedelta(days=period_days)
    
    # Pobierz aktywności z wybranego okresu
    activities = DeviceActivity.query.filter(
        DeviceActivity.device_id == device.id,
        DeviceActivity.timestamp >= start_date
    ).order_by(DeviceActivity.timestamp.desc()).all()
    
    # Oblicz statystyki
    stats = calculate_device_stats(device, activities, period_days)
    
    return render_template('device_report.html',
                         device=device,
                         activities=activities,
                         stats=stats,
                         period_days=period_days,
                         start_date=start_date,
                         generated_at=datetime.now())


@main_bp.route('/device/<int:device_id>/report/pdf')
@login_required
def device_report_pdf(device_id):
    """Generuj raport PDF dla urządzenia"""
    from datetime import datetime, timedelta
    from io import BytesIO
    from flask import request
    
    try:
        from weasyprint import HTML, CSS
        from flask import make_response
        
        # Pobierz urządzenie
        device = Device.query.get_or_404(device_id)
        
        # Pobierz okres z parametru (domyślnie 7 dni)
        period_days = int(request.args.get('period', 7))
        start_date = datetime.now() - timedelta(days=period_days)
        
        # Pobierz aktywności z wybranego okresu
        activities = DeviceActivity.query.filter(
            DeviceActivity.device_id == device.id,
            DeviceActivity.timestamp >= start_date
        ).order_by(DeviceActivity.timestamp.desc()).all()
        
        # Oblicz statystyki
        stats = calculate_device_stats(device, activities, period_days)
        
        # Renderuj HTML
        html_content = render_template('device_report.html',
                                      device=device,
                                      activities=activities,
                                      stats=stats,
                                      period_days=period_days,
                                      start_date=start_date,
                                      generated_at=datetime.now(),
                                      pdf_mode=True)
        
        # Konwertuj do PDF
        pdf = HTML(string=html_content).write_pdf()
        
        # Przygotuj response
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=raport_{device.ip_address}_{period_days}dni.pdf'
        
        return response
        
    except ImportError:
        flash('⚠️ Biblioteka WeasyPrint nie jest zainstalowana. Zainstaluj ją poleceniem: pip install weasyprint', 'warning')
        return redirect(url_for('main.device_detail', device_id=device_id))
    except Exception as e:
        logger.error(f"❌ Błąd generowania PDF: {e}")
        flash(f'Błąd generowania PDF: {str(e)}', 'error')
        return redirect(url_for('main.device_detail', device_id=device_id))


@main_bp.route('/device/<int:device_id>/report/<int:report_id>/send-email', methods=['POST'])
@login_required
def send_report_email(device_id, report_id):
    """Wyślij raport emailem"""
    from datetime import datetime, timedelta
    from app.models import DeviceReport, EmailRecipient
    from core.email_manager import email_manager
    from flask import request
    
    try:
        from weasyprint import HTML
        
        device = Device.query.get_or_404(device_id)
        report = DeviceReport.query.get_or_404(report_id)
        
        # Pobierz email z formularza
        email = request.form.get('email')
        if not email:
            return jsonify({'success': False, 'error': 'Nie podano adresu email'}), 400
        
        # Wygeneruj raport PDF
        period_days = report.period_days
        start_date = datetime.now() - timedelta(days=period_days)
        
        activities = DeviceActivity.query.filter(
            DeviceActivity.device_id == device.id,
            DeviceActivity.timestamp >= start_date
        ).order_by(DeviceActivity.timestamp.desc()).all()
        
        stats = calculate_device_stats(device, activities, period_days)
        
        html_content = render_template('device_report.html',
                                      device=device,
                                      activities=activities,
                                      stats=stats,
                                      period_days=period_days,
                                      start_date=start_date,
                                      generated_at=datetime.now(),
                                      pdf_mode=True)
        
        pdf_data = HTML(string=html_content).write_pdf()
        
        # Wyślij email
        subject = f'Raport urządzenia {device.ip_address} ({report.period_name})'
        body = f'''
        <h2>Raport urządzenia sieciowego</h2>
        <p><strong>Urządzenie:</strong> {device.ip_address}</p>
        <p><strong>Okres:</strong> {report.period_name} ({period_days} dni)</p>
        <p><strong>Data wygenerowania:</strong> {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>W załączniku znajduje się szczegółowy raport w formacie PDF.</p>
        <br>
        <p style="color: #999;">LAN Monitor - System monitorowania sieci lokalnej</p>
        '''
        
        filename = f'raport_{device.ip_address}_{period_days}dni.pdf'
        
        success = email_manager.send_email(
            to_email=email,
            subject=subject,
            body=body,
            html=True,
            attachment=pdf_data,
            attachment_name=filename
        )
        
        if success:
            logger.info(f"✅ Wysłano raport na email: {email}")
            return jsonify({'success': True, 'message': f'Raport został wysłany na adres {email}'})
        else:
            return jsonify({'success': False, 'error': 'Nie udało się wysłać emaila'}), 500
            
    except ImportError:
        return jsonify({'success': False, 'error': 'Biblioteka WeasyPrint nie jest zainstalowana'}), 500
    except Exception as e:
        logger.error(f"❌ Błąd wysyłania raportu emailem: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@main_bp.route('/device/<int:device_id>/report/<int:report_id>/delete', methods=['POST'])
@login_required
def delete_device_report(device_id, report_id):
    """Usuń raport z historii"""
    try:
        from app.models import DeviceReport
        
        # Sprawdź czy urządzenie istnieje
        device = Device.query.get_or_404(device_id)
        
        # Znajdź raport
        report = DeviceReport.query.filter_by(id=report_id, device_id=device_id).first()
        
        if not report:
            return jsonify({'success': False, 'error': 'Raport nie został znaleziony'}), 404
        
        # Usuń raport
        db.session.delete(report)
        db.session.commit()
        
        logger.info(f"Usunięto raport {report_id} dla urządzenia {device.ip_address}")
        return jsonify({'success': True, 'message': 'Raport został usunięty'})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Błąd usuwania raportu: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


def calculate_device_stats(device, activities, period_days):
    """Oblicz statystyki dla urządzenia"""
    from datetime import datetime, timedelta
    
    if not activities:
        return {
            'total_traffic_in': 0,
            'total_traffic_out': 0,
            'total_traffic': 0,
            'avg_traffic_per_day': 0,
            'max_traffic_in': 0,
            'max_traffic_out': 0,
            'min_traffic_in': 0,
            'min_traffic_out': 0,
            'avg_traffic_in': 0,
            'avg_traffic_out': 0,
            'uptime_percentage': 0,
            'total_records': 0,
            'top_hours': []
        }
    
    # Podstawowe statystyki
    total_in = sum(a.bytes_received for a in activities)
    total_out = sum(a.bytes_sent for a in activities)
    total = total_in + total_out
    
    traffic_in_list = [a.bytes_received for a in activities if a.bytes_received > 0]
    traffic_out_list = [a.bytes_sent for a in activities if a.bytes_sent > 0]
    
    # Analiza godzin aktywności
    hour_traffic = {}
    for activity in activities:
        hour = activity.timestamp.hour
        if hour not in hour_traffic:
            hour_traffic[hour] = 0
        hour_traffic[hour] += activity.bytes_received + activity.bytes_sent
    
    # Top 5 najbardziej aktywnych godzin
    top_hours = sorted(hour_traffic.items(), key=lambda x: x[1], reverse=True)[:5]
    top_hours_formatted = [(f"{h:02d}:00-{h:02d}:59", format_bytes(traffic)) for h, traffic in top_hours]
    
    # Oblicz uptime (procent czasu z aktywnością)
    # Zakładamy że każdy rekord = 1 minuta aktywności
    total_minutes_in_period = period_days * 24 * 60
    active_minutes = len(activities)  # Przybliżenie
    uptime_percentage = (active_minutes / total_minutes_in_period * 100) if total_minutes_in_period > 0 else 0
    
    return {
        'total_traffic_in': format_bytes(total_in),
        'total_traffic_out': format_bytes(total_out),
        'total_traffic': format_bytes(total),
        'total_traffic_in_raw': total_in,
        'total_traffic_out_raw': total_out,
        'total_traffic_raw': total,
        'avg_traffic_per_day': format_bytes(total / period_days if period_days > 0 else 0),
        'max_traffic_in': format_bytes(max(traffic_in_list)) if traffic_in_list else '0 B',
        'max_traffic_out': format_bytes(max(traffic_out_list)) if traffic_out_list else '0 B',
        'min_traffic_in': format_bytes(min(traffic_in_list)) if traffic_in_list else '0 B',
        'min_traffic_out': format_bytes(min(traffic_out_list)) if traffic_out_list else '0 B',
        'avg_traffic_in': format_bytes(sum(traffic_in_list) / len(traffic_in_list)) if traffic_in_list else '0 B',
        'avg_traffic_out': format_bytes(sum(traffic_out_list) / len(traffic_out_list)) if traffic_out_list else '0 B',
        'uptime_percentage': round(uptime_percentage, 2),
        'total_records': len(activities),
        'top_hours': top_hours_formatted
    }
