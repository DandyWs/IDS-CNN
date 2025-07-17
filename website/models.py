from . import db
from flask_login import UserMixin # type: ignore
from sqlalchemy.sql import func
from flask import current_app as app
from datetime import datetime

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    profile_pic = db.Column(db.String(150), nullable=True, default='static/default.png')

    def __repr__(self):
        return f'<User {self.username}>'
    
class LiveCapture(db.Model):
    __tablename__ = 'live_capture'
    id = db.Column(db.Integer, primary_key=True)
    real_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    srcip_real = db.Column(db.String(50))
    dstip_real = db.Column(db.String(50))
    protocol_real = db.Column(db.String(20))
    length_real = db.Column(db.Integer)
    info_real = db.Column(db.String(255))
    Attack = db.Column(db.Integer)  # 1 for attack, 0 for normal traffic

    def __repr__(self):
        return f'<LiveCapture {self.id} - {self.srcip_real} to {self.dstip_real}>'