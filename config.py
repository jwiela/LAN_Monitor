"""
Konfiguracja aplikacji Flask
"""
import os
from datetime import timedelta
from dotenv import load_dotenv

# Załaduj zmienne środowiskowe z pliku .env
load_dotenv()

# Ścieżka bazowa projektu
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Bazowa konfiguracja aplikacji"""
    
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Database
    db_path = os.path.join(basedir, 'database', 'lan_monitor.db')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URI', f'sqlite:///{db_path}')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # Network
    NETWORK_INTERFACE = os.getenv('NETWORK_INTERFACE', 'eth0')
    NETWORK_RANGE = os.getenv('NETWORK_RANGE', '192.168.1.0/24')
    SCAN_INTERVAL = int(os.getenv('SCAN_INTERVAL', 300))  # sekundy
    TRAFFIC_UPDATE_INTERVAL = int(os.getenv('TRAFFIC_UPDATE_INTERVAL', 60))  # sekundy
    
    # Automatyczne skanowanie sieci
    NETWORK_SCAN_ENABLED = os.getenv('NETWORK_SCAN_ENABLED', 'true').lower() == 'true'
    NETWORK_SCAN_INTERVAL = int(os.getenv('NETWORK_SCAN_INTERVAL', 60))  # sekundy (domyślnie 1 minuta)
    
    # InfluxDB (opcjonalnie)
    INFLUXDB_ENABLED = os.getenv('INFLUXDB_ENABLED', 'false').lower() == 'true'
    INFLUXDB_URL = os.getenv('INFLUXDB_URL', 'http://localhost:8086')
    INFLUXDB_TOKEN = os.getenv('INFLUXDB_TOKEN', '')
    INFLUXDB_ORG = os.getenv('INFLUXDB_ORG', 'lan_monitor')
    INFLUXDB_BUCKET = os.getenv('INFLUXDB_BUCKET', 'network_traffic')
    
    # Grafana
    GRAFANA_URL = os.getenv('GRAFANA_URL', 'http://192.168.1.12:3000')
    GRAFANA_ENABLED = os.getenv('GRAFANA_ENABLED', 'false').lower() == 'true'
    GRAFANA_DASHBOARD_UID = os.getenv('GRAFANA_DASHBOARD_UID', '')
    
    # Email
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', '')
    ALERT_EMAIL = os.getenv('ALERT_EMAIL', '')
    
    # Admin
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin')


class DevelopmentConfig(Config):
    """Konfiguracja dla środowiska deweloperskiego"""
    DEBUG = True


class ProductionConfig(Config):
    """Konfiguracja dla środowiska produkcyjnego"""
    DEBUG = False


# Wybór konfiguracji na podstawie zmiennej środowiskowej
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
