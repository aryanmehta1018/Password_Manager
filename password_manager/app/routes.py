import os
from flask import render_template, redirect, url_for, request, flash, Blueprint
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User,Passwords

main = Blueprint('main', __name__)


@main.route('/')
def home():
    return """
    <div style="text-align: center; margin-top: 50px;font-size: 24px;">
        <p>Welcome to the Password Manager!</p> 
        <p><a href='/login'>Click Here To Login</a></p>
    </div>
    """

@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'danger')
            return redirect(url_for('main.register'))  

        new_user = User(email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('main.login'))  

    return render_template('register.html')

@main.route('/login', methods=['GET', 'POST'])  
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('main.dashboard'))  
        else:
            flash('Invalid credentials.', 'danger')

    return render_template('login.html')


@main.route('/add_password', methods=['GET', 'POST'])
@login_required
def add_password():
    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']  

        new_password = Passwords(user_id=current_user.id, website=website, username=username, password=password)
        db.session.add(new_password)
        db.session.commit()

        return redirect(url_for('main.dashboard'))
    
    return render_template('add_password.html')


@main.route('/dashboard')
@login_required  
def dashboard():
    return render_template('dashboard.html', user=current_user)


@main.route('/debug-templates')
def debug_templates():
    template_path = os.path.join(os.getcwd(), 'app/templates')
    templates = os.listdir(template_path)
    return f"Available templates: {templates}"


@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.login'))  
