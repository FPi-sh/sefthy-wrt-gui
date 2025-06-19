from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    first_login = db.Column(db.Boolean, default=True)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Config(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), default='')

class Version(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.String(255), default='')

class SelectedBridge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bridge_name = db.Column(db.String(50), nullable=False)
