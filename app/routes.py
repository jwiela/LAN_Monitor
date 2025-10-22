"""
Blueprint głównych stron - dashboard, strona główna, szczegóły urządzenia
"""
from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user
from app.models import Device, DeviceActivity, Alert
from sqlalchemy import desc

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
