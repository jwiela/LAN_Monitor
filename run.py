#!/usr/bin/env python3
"""
Główny plik uruchomieniowy aplikacji LAN Monitor
"""
import os
from app import create_app

# Pobierz nazwę środowiska z zmiennej środowiskowej
config_name = os.getenv('FLASK_ENV', 'development')

# Utwórz aplikację
app = create_app(config_name)

if __name__ == '__main__':
    # Uruchom serwer deweloperski
    # W produkcji użyj gunicorn lub innego WSGI servera
    app.run(
        host='0.0.0.0',  # Dostępne z zewnątrz
        port=5000,
        debug=app.config['DEBUG']
    )
