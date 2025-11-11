"""
Inicjalizacja aplikacji Flask i jej rozszerzeń
"""
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from config import config

# Inicjalizacja rozszerzeń
db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()

def create_app(config_name='default'):
    """
    Factory function do tworzenia aplikacji Flask
    
    Args:
        config_name: Nazwa konfiguracji ('development', 'production', 'default')
    
    Returns:
        Skonfigurowana aplikacja Flask
    """
    app = Flask(__name__)
    
    # Załaduj konfigurację
    app.config.from_object(config[config_name])
    
    # Upewnij się, że katalog database istnieje
    basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    db_dir = os.path.join(basedir, 'database')
    os.makedirs(db_dir, exist_ok=True)
    
    # Inicjalizacja rozszerzeń z aplikacją
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    
    # Konfiguracja Flask-Login
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Proszę się zalogować, aby uzyskać dostęp do tej strony.'
    login_manager.login_message_category = 'info'
    
    # Rejestracja blueprintów
    from app.auth import auth_bp
    from app.routes import main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    
    # Context processor - dostępne w wszystkich szablonach
    @app.context_processor
    def inject_unread_alerts():
        """Dodaj liczbę nieprzeczytanych alertów do kontekstu szablonów"""
        from app.models import Alert
        def get_unread_alerts_count():
            return Alert.query.filter_by(is_read=False).count()
        return dict(get_unread_alerts_count=get_unread_alerts_count)
    
    # Inicjalizuj traffic manager
    from core.traffic_manager import traffic_manager
    traffic_manager.init_app(app)
    
    # Inicjalizuj scanner manager
    from core.scanner_manager import scanner_manager
    scanner_manager.init_app(app)
    
    with app.app_context():
        # Importuj modele
        from app import models
        
        # Utwórz tabele w bazie danych
        db.create_all()
        
        # Inicjalizuj domyślnego użytkownika admin
        models.init_default_user()
    
    return app
