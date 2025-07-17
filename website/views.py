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
from flask_login import login_required, current_user  # For protecting routes
from .models import User  # Import User model

views = Blueprint('views', __name__)
@views.route('/')
@login_required
def home():
    return render_template('home.html')
