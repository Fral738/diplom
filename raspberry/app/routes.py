import datetime

from . import app, other_users, other_logs, startup_time
from .models import find_document, insert_document, delete_document, update_document
from flask import render_template, request, redirect, url_for, jsonify, json
from bson import ObjectId
import requests
import time


@app.route('/response_check', methods=['GET'])
def response_check():
    if request.method == 'GET':
        timer = str(datetime.timedelta(seconds=time.time() - startup_time)).split('.')
        return timer[0]


@app.route('/', methods=['GET'])
def index():
    row = find_document(other_users)
    return render_template('index.html', rows=row)


@app.route('/delete_user', methods=['POST'])
def delete_user():
    if request.method == 'POST':
        for line in request.form.getlist('delete_checkbox'):
            delete_document(other_users, {'_id': ObjectId(line)})
        return redirect('/')


@app.route('/get_documents', methods=['POST'])
def get_documents():
    obj_id, new_id = '', []
    find_user = find_document(other_users)
    get_user = request.json
    for i in get_user:
        for key, value in i.items():
            if key == '_id':
                obj_id = value
        insert = {'_id': ObjectId(obj_id), 'last_name': i['last_name'], 'first_name': i['first_name'],
                  'middle_name': i['middle_name'], 'uid': i['uid']}
        if not find_user:
            insert_document(other_users, insert)
        else:
            for j in find_user:
                for key, value in j.items():
                    if key == '_id':
                        new_id.append(value)
        if ObjectId(obj_id) not in new_id:
            insert_document(other_users, insert)
    return 'ok'


@app.route('/receive_change', methods=['POST'])
def receive_change():
    id = ''
    receive = request.json
    for i in receive:
        for key, value in i.items():
            if key == '_id':
                id = value
        update_document(other_users,
                        {"_id": ObjectId(id)}, {'last_name': i['last_name'], 'first_name': i['first_name'],
                                                'middle_name': i['middle_name'], 'uid': i['uid']})
        return redirect('/')


@app.route('/receive_delete', methods=['POST'])
def receive_delete():
    get_user = request.json
    for i in get_user:
        delete_document(other_users, {'_id': ObjectId(i)})


