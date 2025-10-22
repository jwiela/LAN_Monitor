"""
Blueprint głównych stron - dashboard, strona główna, szczegóły urządzenia
"""
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from app.models import Device, DeviceActivity, Alert
from app import db
from sqlalchemy import desc
import threading

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
    """Dashboard z listą urządzeń w sieci"""
    # Pobierz wszystkie urządzenia
    devices = Device.query.order_by(desc(Device.last_seen)).all()
    
    # Statystyki
    total_devices = Device.query.count()
    online_devices = Device.query.filter_by(is_online=True).count()
    new_devices = Device.query.filter_by(is_new=True).count()
    
    # Ostatnie alerty
    recent_alerts = Alert.query.filter_by(is_read=False).order_by(desc(Alert.created_at)).limit(5).all()
    
    return render_template('dashboard.html',
                         devices=devices,
                         total_devices=total_devices,
                         online_devices=online_devices,
                         new_devices=new_devices,
                         recent_alerts=recent_alerts)


@main_bp.route('/device/<int:device_id>')
@login_required
def device_detail(device_id):
    """Szczegóły urządzenia - ruch sieciowy, statystyki"""
    from datetime import datetime, timedelta
    from flask import current_app
    from core.traffic_manager import traffic_manager
    
    device = Device.query.get_or_404(device_id)
    
    # Pobierz aktywność z ostatnich 24h
    activities = DeviceActivity.query.filter_by(device_id=device_id)\
        .order_by(desc(DeviceActivity.timestamp))\
        .limit(100)\
        .all()
    
    # Pobierz bieżące prędkości (KB/s)
    rates = traffic_manager.traffic_monitor.get_current_rates()
    device_rate = rates.get(device.ip_address, (0, 0))
    
    download_rate = f"{device_rate[0]:.2f} KB/s"
    upload_rate = f"{device_rate[1]:.2f} KB/s"
    
    # Oblicz całkowity ruch z ostatnich 24h
    total_bytes_in = sum(a.bytes_received for a in activities)
    total_bytes_out = sum(a.bytes_sent for a in activities)
    total_traffic = f"{(total_bytes_in + total_bytes_out) / 1024 / 1024:.2f} MB"
    
    # Ostatnia aktywność
    if device.last_seen:
        last_seen = device.last_seen.strftime('%Y-%m-%d %H:%M:%S')
    else:
        last_seen = "Nigdy"
    
    # Konfiguracja Grafana
    grafana_enabled = current_app.config.get('GRAFANA_ENABLED', False)
    grafana_url = current_app.config.get('GRAFANA_URL', 'http://localhost:3000')
    dashboard_uid = 'device-traffic'  # UID dashboardu w Grafanie
    
    return render_template('device_detail.html',
                         device=device,
                         activities=activities,
                         download_rate=download_rate,
                         upload_rate=upload_rate,
                         total_traffic=total_traffic,
                         last_seen=last_seen,
                         grafana_enabled=grafana_enabled,
                         grafana_url=grafana_url,
                         dashboard_uid=dashboard_uid)


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
    
    device = Device.query.get_or_404(device_id)
    
    # Pobierz bieżące prędkości (KB/s) z traffic monitor
    rates = traffic_manager.traffic_monitor.get_current_rates()
    device_rate = rates.get(device.ip_address, (0, 0))
    
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
