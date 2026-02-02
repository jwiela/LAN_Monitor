"""
Blueprint autoryzacji - logowanie, wylogowanie, zmiana hasła
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
from app import db
from app.models import User

auth_bp = Blueprint('auth', __name__)


"""Strona logowania"""
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Jeśli użytkownik jest już zalogowany, przekieruj do dashboardu
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        # Walidacja
        if not username or not password:
            flash('Proszę podać nazwę użytkownika i hasło.', 'error')
            return render_template('login.html')
        
        # Znajdź użytkownika
        user = User.query.filter_by(username=username).first()
        
        # Sprawdź hasło
        if user and user.check_password(password):
            # Zaloguj użytkownika
            login_user(user, remember=remember)
            
            # Aktualizuj czas ostatniego logowania
            user.last_login = datetime.now()
            db.session.commit()
            
            flash(f'Witaj, {user.username}!', 'success')
            
            # Przekieruj do strony, z której użytkownik próbował się dostać
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
        else:
            flash('Nieprawidłowa nazwa użytkownika lub hasło.', 'error')
    
    return render_template('login.html')

"""Wylogowanie użytkownika"""
@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Zostałeś wylogowany.', 'info')
    return redirect(url_for('auth.login'))

"""Zmiana hasła użytkownika"""
@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Walidacja
        if not current_password or not new_password or not confirm_password:
            flash('Proszę wypełnić wszystkie pola.', 'error')
            return render_template('change_password.html')
        
        # Sprawdź aktualne hasło
        if not current_user.check_password(current_password):
            flash('Aktualne hasło jest nieprawidłowe.', 'error')
            return render_template('change_password.html')
        
        # Sprawdź czy nowe hasła się zgadzają
        if new_password != confirm_password:
            flash('Nowe hasła nie są identyczne.', 'error')
            return render_template('change_password.html')
        
        # Sprawdź długość hasła
        if len(new_password) < 4:
            flash('Hasło musi mieć co najmniej 4 znaki.', 'error')
            return render_template('change_password.html')
        
        # Zmień hasło
        current_user.set_password(new_password)
        db.session.commit()
        
        flash('Hasło zostało zmienione pomyślnie!', 'success')
        return redirect(url_for('main.dashboard'))
    
    return render_template('change_password.html')
