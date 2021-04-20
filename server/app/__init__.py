from flask import Flask
from pymongo import MongoClient
from flask_login import LoginManager


app = Flask(__name__)
app.secret_key = 'secret secret'
client = MongoClient('mongodb', username='admin', password='admin')
db = client.test_db
users = db.users
deleted_users = db.deleted_users
logs = db.logs
manager = LoginManager(app)

from . import routes
