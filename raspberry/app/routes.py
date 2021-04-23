import datetime

from . import app, users, logs
from flask import render_template, request, redirect, url_for, jsonify
from flask_login import login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
from bson import ObjectId
import requests

@app.route('/')
def index():
    return 'hello'


@app.route('/response_check', methods=['GET'])
def response_check():
    if request.method == 'GET':
        # data = {
        #     "users_counter": users.count_documents({}),
        #     "logs_counter": logs.count_documents({})
        # }
        return 'hello'

@app.route('/get_documents', methods=['POST'])
def get_documents():
    if request.method == 'POST':
        data = request.data
        users.insert_one(data)
        return redirect('/')

