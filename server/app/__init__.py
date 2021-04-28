from flask import Flask
from pymongo import MongoClient
from flask_login import LoginManager
import time

app = Flask(__name__)
app.secret_key = 'secret secret'
client = MongoClient('mongodb')
db = client.test_db
users = db.users
deleted_users = db.deleted_users
logs = db.logs
manager = LoginManager(app)
devices = db.devices
startup_time = time.time()

from . import routes
