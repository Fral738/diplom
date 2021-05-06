from flask import Flask, jsonify
from pymongo import MongoClient
from flask_login import LoginManager
import logging
from logstash_async.handler import AsynchronousLogstashHandler
import time

app = Flask(__name__)
app.secret_key = 'secret secret'
client = MongoClient('mongodb')
db = client.test_db
users = db.users
deleted_users = db.deleted_users
manager = LoginManager(app)
devices = db.devices

host = 'logstash'
port = 5000
logger = logging.getLogger('simple-app')
logger.setLevel(logging.DEBUG)
async_handler = AsynchronousLogstashHandler(host, port, database_path=None)
logger.addHandler(async_handler)
startup_time = time.time()

from . import routes
