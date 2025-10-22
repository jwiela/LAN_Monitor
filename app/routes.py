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
    device = Device.query.get_or_404(device_id)
    
    # Pobierz aktywność z ostatnich 24h
    activities = DeviceActivity.query.filter_by(device_id=device_id)\
        .order_by(desc(DeviceActivity.timestamp))\
        .limit(100)\
        .all()
    
    return render_template('device_detail.html',
                         device=device,
                         activities=activities)


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
