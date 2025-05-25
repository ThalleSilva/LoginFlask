from db import db
from flask_login import UserMixin


class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    nome = db.Column(db.String(30), unique=True)
    senha = db.Column(db.String())
    email = db.Column(db.String(), unique=True)
    