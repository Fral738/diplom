from flask import Flask
from pymongo import MongoClient
from flask_login import LoginManager
import time

app = Flask(__name__)
app.secret_key = 'secret secret'
client = MongoClient('mongodb')
db = client.test_db
other_users = db.other_users
other_logs = db.other_logs
startup_time = time.time()
manager = LoginManager(app)

from . import routes
