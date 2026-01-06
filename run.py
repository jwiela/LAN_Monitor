#!/usr/bin/env python3
"""
Główny plik uruchomieniowy aplikacji LAN Monitor
"""
import os
import logging
from app import create_app
from core.traffic_manager import traffic_manager
from core.scanner_manager import scanner_manager

# Konfiguracja logowania
log_file = os.path.join(os.path.dirname(__file__), 'flask.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

# Pobierz nazwę środowiska z zmiennej środowiskowej
config_name = os.getenv('FLASK_ENV', 'development')

# Utwórz aplikację
app = create_app(config_name)

if __name__ == '__main__':
    # Uruchom traffic manager i scanner manager w osobnych wątkach
    try:
        traffic_manager.start()
        scanner_manager.start()
        
        # Uruchom serwer deweloperski
        # W produkcji użyj gunicorn lub innego WSGI servera
        app.run(
            host='0.0.0.0',  # Dostępne z zewnątrz
            port=5000,
            debug=app.config['DEBUG']
        )
    except KeyboardInterrupt:
        print("\n🛑 Zatrzymywanie aplikacji...")
    finally:
        traffic_manager.stop()
        scanner_manager.stop()
