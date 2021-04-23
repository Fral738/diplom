from flask import Flask
from pymongo import MongoClient
from flask_login import LoginManager


app = Flask(__name__)
app.secret_key = 'secret secret'
client = MongoClient('mongodb')
db = client.test_db
users = db.users
logs = db.logs
manager = LoginManager(app)

from . import routes
