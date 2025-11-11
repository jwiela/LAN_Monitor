"""
Modele bazy danych dla aplikacji
"""
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager
from config import Config


class User(UserMixin, db.Model):
    """Model użytkownika"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        """Ustaw zahashowane hasło"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Sprawdź poprawność hasła"""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'


class Device(db.Model):
    """Model urządzenia w sieci"""
    __tablename__ = 'devices'
    
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), unique=False, nullable=True)  # Format: AA:BB:CC:DD:EE:FF, może być None
    ip_address = db.Column(db.String(15), nullable=True)  # IPv4
    hostname = db.Column(db.String(255), nullable=True)
    vendor = db.Column(db.String(255), nullable=True)  # Producent na podstawie MAC
    device_type = db.Column(db.String(50), nullable=True)  # np. 'computer', 'phone', 'router'
    first_seen = db.Column(db.DateTime, default=datetime.now)
    last_seen = db.Column(db.DateTime, default=datetime.now)
    is_online = db.Column(db.Boolean, default=True)
    is_new = db.Column(db.Boolean, default=True)  # Flaga dla alertów o nowym urządzeniu
    
    # Relacja do aktywności
    activities = db.relationship('DeviceActivity', backref='device', lazy='dynamic', 
                                cascade='all, delete-orphan')
    
    def update_last_seen(self):
        """Aktualizuj czas ostatniego widzenia urządzenia"""
        self.last_seen = datetime.now()
        self.is_online = True
        db.session.commit()
    
    def mark_offline(self):
        """Oznacz urządzenie jako offline"""
        self.is_online = False
        db.session.commit()
    
    def __repr__(self):
        return f'<Device {self.mac_address} ({self.ip_address})>'


class DeviceActivity(db.Model):
    """Model aktywności urządzenia (ruch sieciowy)"""
    __tablename__ = 'device_activities'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now, index=True)
    
    # Statystyki ruchu (w bajtach)
    bytes_sent = db.Column(db.BigInteger, default=0)
    bytes_received = db.Column(db.BigInteger, default=0)
    packets_sent = db.Column(db.Integer, default=0)
    packets_received = db.Column(db.Integer, default=0)
    
    # Statystyki protokołów (JSON: {"http": 1234, "https": 5678, ...})
    protocol_stats = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<DeviceActivity {self.device_id} at {self.timestamp}>'


class Alert(db.Model):
    """Model alertów systemowych"""
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(50), nullable=False)  # 'new_device', 'unusual_traffic', etc.
    severity = db.Column(db.String(20), default='info')  # 'info', 'warning', 'critical'
    message = db.Column(db.Text, nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now, index=True)
    is_read = db.Column(db.Boolean, default=False)
    is_sent = db.Column(db.Boolean, default=False)  # Czy alert został wysłany mailem
    
    device = db.relationship('Device', backref='alerts')
    
    def __repr__(self):
        return f'<Alert {self.alert_type} - {self.severity}>'


class EmailRecipient(db.Model):
    """Model odbiorcy powiadomień email"""
    __tablename__ = 'email_recipients'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=True)  # Opcjonalna nazwa odbiorcy
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # Typy alertów, które mają być wysyłane (JSON lub osobne kolumny boolean)
    notify_new_device = db.Column(db.Boolean, default=True)
    notify_device_offline = db.Column(db.Boolean, default=True)
    notify_device_online = db.Column(db.Boolean, default=True)
    notify_unusual_traffic = db.Column(db.Boolean, default=False)
    notify_high_traffic = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<EmailRecipient {self.email}>'
    
    def should_notify(self, alert_type):
        """Sprawdź czy odbiorca powinien otrzymać powiadomienie o danym typie alertu"""
        mapping = {
            'new_device': self.notify_new_device,
            'device_offline': self.notify_device_offline,
            'device_online': self.notify_device_online,
            'unusual_traffic': self.notify_unusual_traffic,
            'high_traffic': self.notify_high_traffic,
        }
        return mapping.get(alert_type, False)


class DeviceReport(db.Model):
    """Model wygenerowanego raportu urządzenia"""
    __tablename__ = 'device_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    period_days = db.Column(db.Integer, nullable=False)  # 1, 7, 30
    generated_at = db.Column(db.DateTime, default=datetime.now)
    file_path = db.Column(db.String(500), nullable=True)  # Ścieżka do pliku PDF (opcjonalne)
    
    # Relacja
    device = db.relationship('Device', backref=db.backref('reports', lazy='dynamic'))
    
    def __repr__(self):
        return f'<DeviceReport {self.device.ip_address} - {self.period_days}d>'
    
    @property
    def period_name(self):
        """Zwróć nazwę okresu"""
        if self.period_days == 1:
            return 'Dzienny'
        elif self.period_days == 7:
            return 'Tygodniowy'
        elif self.period_days == 30:
            return 'Miesięczny'
        return f'{self.period_days} dni'


@login_manager.user_loader
def load_user(user_id):
    """Callback do ładowania użytkownika dla Flask-Login"""
    return User.query.get(int(user_id))


def init_default_user():
    """
    Inicjalizuj domyślnego użytkownika admin, jeśli nie istnieje
    """
    admin = User.query.filter_by(username=Config.ADMIN_USERNAME).first()
    if not admin:
        admin = User(username=Config.ADMIN_USERNAME)
        admin.set_password(Config.ADMIN_PASSWORD)
        db.session.add(admin)
        db.session.commit()
        print(f"✓ Utworzono domyślnego użytkownika: {Config.ADMIN_USERNAME}")
