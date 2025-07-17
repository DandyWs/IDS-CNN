from flask import Flask, render_template, request, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy # type: ignore
import os
from os import path
from flask_login import LoginManager # type: ignore
import pandas as pd
from werkzeug.utils import secure_filename
from keras.models import load_model
from flask_migrate import Migrate

from preprocessing.preprocess import preprocess_csv
from website.livecapture import live_results, start_capture_thread

db = SQLAlchemy()
migrate = Migrate()
# from flask_migrate import Migrate
# migrate = Migrate()
DB_NAME = 'database.db'

UPLOAD_FOLDER = 'uploads'

def create_app():
    app = Flask(__name__)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Ensure upload folder exists
    # Load configuration
    app.config['SECRET_KEY'] = 'Dandy123#'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:dandyj4s4t1rt4#@localhost/skripsi_final'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    # Initialize Flask-Migrate
    # Migrate(app, db)
    migrate.init_app(app, db)

        
    # # Initialize extensions, blueprints, etc.
    # with app.app_context():
    #     from . import routes  # Import routes to register them
    #     from .extensions import db, migrate  # Import extensions

    #     db.init_app(app)
    #     migrate.init_app(app, db)
    from .views import views as views_blueprint
    from .auth import auth as auth_blueprint
    from .cnn import cnn as cnn_blueprint  # Import CNN blueprint if needed
    
    app.register_blueprint(views_blueprint, url_prefix='/')
    app.register_blueprint(auth_blueprint, url_prefix='/')
    app.register_blueprint(cnn_blueprint, url_prefix='/')

    from .models import User  # Import models to ensure they are registered with SQLAlchemy
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist

    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'  # Redirect to login page if user is not authenticated
    @login_manager.user_loader
    def load_user(user_id):
        from .models import User  # Import User model to avoid circular import
        return User.query.get(int(user_id))  # Return the user object by ID
    # Initialize Flask-Migrate
    # migrate.init_app(app, db)
    
    return app