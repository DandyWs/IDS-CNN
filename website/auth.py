from flask import Blueprint, render_template
from flask import current_app as app
from flask import request, redirect, url_for
from flask import flash
from flask import session
from flask import jsonify
from flask import abort
from flask import make_response
from flask import g
from flask import send_from_directory
from scapy.all import sniff, IP, TCP, UDP
import os
import pandas as pd
import datetime
import psutil
import time
from .models import User, LiveCapture  # Import User model
from . import db  # Import database instance
from werkzeug.utils import secure_filename  # For secure file handling
from werkzeug.security import generate_password_hash, check_password_hash  # For password hashing
from flask_login import login_required,login_user,logout_user,current_user  # For protecting routes
from website.livecapture import get_available_interfaces

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Here you would typically check the username and password against a database
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                # Password matches, log the user in
                session['user'] = user.username  # Store username in session
                session['user_id'] = user.id  # Store user ID in session
                login_user(user)  # Use Flask-Login to log the user in
                flash('Login successful!', 'success')
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password. Please try again.', 'error')
                return redirect(url_for('auth.login'))
        
        else:
            flash('Login failed. Email not found.', 'error')
            return redirect(url_for('auth.login'))
    return render_template('user/login.html')
    

@auth.route('/logout')
@login_required
def logout():
    logout_user()  # Use Flask-Login to log the user out
    session.pop('user', None)  # Remove user from session
    flash('You have been logged out.', 'success')
    
    return redirect(url_for('views.home'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Email is required!', 'error')
            return redirect(url_for('auth.register'))
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('auth.register'))
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists. Please choose a different one.', 'error')
            return redirect(url_for('auth.register'))
        username_exists = User.query.filter_by(username=username).first()
        if username_exists:
            flash('Username already exists. Please choose a different one.', 'error')
            return redirect(url_for('auth.register'))
        # Here you would typically save the new user to a database
        # Hash the password for security
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        # Truncate if longer than 255 characters (not recommended, but for varchar(255) compatibility)
        new_user = {
            'email': email,
            'username': username,
            'password': hashed_password
        }
        db.session.add(User(email=new_user['email'], username=new_user['username'], password=new_user['password']))
        db.session.commit()  # Commit the new user to the database
        # login_user(user, remember=True)
        flash(f'User {username} registered successfully!', 'success')
        return redirect(url_for('auth.list_users'))
    
    return render_template('user/register.html')

@auth.route('/profile')
def profile():
    if 'user' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('auth.login'))
    
    username = session['user']
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('auth.login'))
    return render_template('user/profile.html', user=user)   

@auth.route('/edit_profile/<int:user_id>', methods=['GET', 'POST'])
def edit_profile(user_id):
    user = User.query.get_or_404(user_id)
    # Optional: Only allow editing if the logged-in user matches
    if 'user' not in session or session['user'] != user.username:
        flash('You are not authorized to edit this profile.', 'danger')
        return redirect(url_for('auth.profile'))

    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        file = request.files.get('profile_pic')

        if not email or not username:
            flash('Email and username are required.', 'danger')
            return redirect(url_for('auth.edit_profile', user_id=user.id))

        user.email = email
        user.username = username

        if file and file.filename:
            filename = secure_filename(file.filename)
            upload_folder = os.path.join(app.root_path, 'static', 'profile_pics')
            os.makedirs(upload_folder, exist_ok=True)  # Ensure the upload folder exists
            filepath = os.path.join(upload_folder, filename)
            file.save(filepath)
            user.profile_pic = f'static/profile_pics/{filename}'  # Save only the relative path in the database
        else:
            user.profile_pic = 'static/default.png'

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('auth.profile'))

    return render_template('user/edit_profile.html', user=user)

@auth.route('/settings')
def settings():
    if 'user' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('auth.login'))
    
    # Here you would typically load user settings from a database
    return render_template('settings.html')

@auth.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('auth.login'))
    
    # Here you would typically delete the user from the database
    username = session.pop('user', None)
    flash(f'Account {username} deleted successfully!', 'success')
    
    return redirect(url_for('views.home'))

@auth.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form.get('username')
        new_password = request.form.get('new_password')
        
        # Here you would typically update the user's password in the database
        flash(f'Password for {username} reset successfully!', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('reset_password.html')

@auth.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        # Here you would typically send a password reset email
        flash(f'Password reset link sent to {email}!', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('forgot_password.html')

@auth.route('/change_email', methods=['GET', 'POST'])
def change_email():
    if 'user' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        new_email = request.form.get('new_email')
        
        # Here you would typically update the user's email in the database
        flash(f'Email changed to {new_email} successfully!', 'success')
        return redirect(url_for('auth.profile'))
    
    return render_template('change_email.html')

@auth.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        
        # Here you would typically check the old password and update the new password in the database
        flash('Password changed successfully!', 'success')
        return redirect(url_for('auth.profile'))
    
    return render_template('change_password.html')

@auth.route('/account_recovery', methods=['GET', 'POST'])
def account_recovery():
    if request.method == 'POST':
        username = request.form.get('username')
        recovery_email = request.form.get('recovery_email')
        
        # Here you would typically send a recovery email or perform some recovery action
        flash(f'Recovery instructions sent to {recovery_email} for user {username}!', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('account_recovery.html')

@auth.route('/two_factor_auth', methods=['GET', 'POST'])
def two_factor_auth():
    if 'user' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        code = request.form.get('code')
        
        # Here you would typically verify the 2FA code
        if code == '123456':
            flash('Two-factor authentication successful!', 'success')
            return redirect(url_for('views.home'))
        else:
            flash('Invalid two-factor authentication code.', 'danger')
            return redirect(url_for('auth.two_factor_auth'))
        
    return render_template('two_factor_auth.html')

@auth.route('/users')
@login_required
def list_users():
    users = User.query.all()
    return render_template('user/users.html', users=users)

@auth.route('/user/<int:user_id>')
@login_required
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user_detail.html', user=user)

@auth.route('/user/create', methods=['GET', 'POST'])
@login_required
def create_user():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        if not email or not username or not password:
            flash('All fields are required.', 'error')
            return redirect(url_for('auth.create_user'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'error')
            return redirect(url_for('auth.create_user'))
        new_user = User(
            email=email,
            username=username,
            password=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully!', 'success')
        return redirect(url_for('auth.list_users'))
    return render_template('create_user.html')

@auth.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.email = request.form.get('email')
        user.username = request.form.get('username')
        password = request.form.get('password')
        if password:
            user.password = generate_password_hash(password)
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('auth.view_user', user_id=user.id))
    return render_template('edit_user.html', user=user)

@auth.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('auth.list_users'))

import time
import psutil
from sqlalchemy import func

@auth.route('/api/dashboard-data')
@login_required
def dashboard_data():
    # Measure upload/download speed over 1 second
    net1 = psutil.net_io_counters()
    time.sleep(1)
    net2 = psutil.net_io_counters()

    upload_speed = (net2.bytes_sent - net1.bytes_sent) / 1024  # KB/s
    download_speed = (net2.bytes_recv - net1.bytes_recv) / 1024  # KB/s
    # Get attack count from database table live_capture where Attack=1
    attack_count = db.session.query(func.count()).select_from(LiveCapture).filter_by(Attack=1).scalar()
    packet_count = db.session.query(func.count()).select_from(LiveCapture).scalar()
    active_interface = psutil.net_if_addrs()
    if active_interface:
        active_interface = list(active_interface.keys())[0]
    else:
        active_interface = 'N/A'
    

    total_traffic = (net2.bytes_sent + net2.bytes_recv) / (1024 * 1024)  # MB
    peak_usage = max(upload_speed, download_speed) / 1024  # MB/s

    active_connections = len(psutil.net_connections(kind='inet'))

    # For chart data, get upload/download for last 6 seconds
    chart_labels = []
    upload_values = []
    download_values = []
    for i in range(6):
        n1 = psutil.net_io_counters()
        time.sleep(1)
        n2 = psutil.net_io_counters()
        up = (n2.bytes_sent - n1.bytes_sent) / 1024  # KB/s
        down = (n2.bytes_recv - n1.bytes_recv) / 1024  # KB/s
        chart_labels.append(time.strftime("%H:%M:%S"))
        upload_values.append(round(up, 2))
        download_values.append(round(down, 2))

    data = {
        "total_traffic": round(total_traffic, 2),
        "active_connections": active_connections,
        "upload_speed": round(upload_speed, 2),
        'attack_count': attack_count,
        "packet_count": packet_count,
        "active_interface": active_interface,
        "download_speed": round(download_speed, 2),
        "peak_usage": round(peak_usage, 3),
        "chart": {
            "labels": chart_labels,
            "upload": upload_values,
            "download": download_values
        }
    }

    return jsonify(data)

@auth.context_processor
def inject_user():
    """Inject the current user into templates."""
    if current_user.is_authenticated:
        return {'current_user': current_user}
    return {'current_user': None}

@auth.context_processor
def inject_profile_pic_url():
    """Inject the profile picture URL into templates."""
    if current_user.is_authenticated and getattr(current_user, 'profile_pic', None):
        return {'profile_pic_url': current_user.profile_pic}
    return {'profile_pic_url': url_for('static', filename='default.png')}

@auth.errorhandler(404)
def page_not_found(e):
    """Custom 404 error handler."""
    return render_template('404.html'), 404

@auth.route('/api/clear-live-capture', methods=['POST'])
def clear_live_capture():
    try:
        from .models import LiveCapture
        num_deleted = LiveCapture.query.delete()
        db.session.commit()
        return '', 200
    except Exception as e:
        print("Error clearing live_capture:", e)
        return 'Error', 500