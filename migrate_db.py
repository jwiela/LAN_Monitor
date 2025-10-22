#!/usr/bin/env python3
"""
Migracja bazy danych - usunięcie unique constraint z mac_address
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db

app = create_app()

with app.app_context():
    print("🔄 Wykonuję migrację bazy danych...")
    print("   Usuwam starą bazę i tworzę nową ze zaktualizowanym schema...")
    
    # Usuń wszystkie tabele
    db.drop_all()
    
    # Utwórz nowe tabele
    db.create_all()
    
    # Inicjalizuj domyślnego użytkownika
    from app.models import init_default_user
    init_default_user()
    
    print("✅ Migracja zakończona pomyślnie!")
    print("   Baza danych została zresetowana.")
