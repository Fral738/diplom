import datetime

from . import app
from flask import render_template, request, flash, redirect, url_for, session, jsonify
from .models import find_document, insert_document, update_document, delete_document
from werkzeug.security import check_password_hash, generate_password_hash
import bson
from . import users, deleted_users, logs


@app.route('/', methods=['GET', 'POST'])
def index():
    if 'username' in session:
        if request.method == 'POST':
            row = (find_document(users, {'last_name': request.form['search']}, True))
            if not row:
                row = (find_document(users, {'first_name': request.form['search']}, True))
                if not row:
                    row = (find_document(users, {'uid': request.form['search']}, True))
        else:
            row = find_document(users)
        return render_template('index.html', rows=row)
    else:
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    role = ''
    password_list = []
    error = None
    if request.method == 'POST':
        login = request.form['username']
        password = request.form['password']
        if login and password:
            result = find_document(users, {'last_name': login}, True)
            if result:
                for i in result:
                    for key, value in i.items():
                        if key == 'role':
                            role = value
                        if key == 'password':
                            password_list.append(value)
                if role == '1':
                    for i in password_list:
                        if check_password_hash(i, password):
                            session['username'] = request.form['username']
                            flash('You were successfully logged in')
                            return redirect(url_for('index'))
    return render_template('login.html', error=error)


@app.route('/users', methods=['GET'])
def user():
    if 'username' in session:
        return render_template('users.html')
    else:
        return redirect(url_for('login'))


@app.route('/add_user', methods=['POST'])
def add_user():
    if 'username' in session:
        if request.method == 'POST':
            check = request.form['role']
            if check == '1':
                one = {'last_name': request.form['last_name'], 'first_name': request.form['first_name'],
                       'middle_name': request.form['middle_name'], 'uid': request.form['uid'],
                       'password': generate_password_hash(request.form['password']), 'role': request.form['role'],
                       'create_date': datetime.datetime.now()}
                insert_document(users, one)
            else:
                one = {'last_name': request.form['last_name'], 'first_name': request.form['first_name'],
                       'middle_name': request.form['middle_name'], 'uid': request.form['uid'],
                       'role': request.form['role'], 'create_date': datetime.datetime.now()}
                insert_document(users, one)
            log = {'action': 'created', 'last_name': request.form['last_name'],
                   'first_name': request.form['first_name'],
                   'middle_name': request.form['middle_name'], 'uid': request.form['uid'],
                   'date': datetime.datetime.now()}
            insert_document(logs, log)
        return redirect('/')
    return redirect(url_for('login'))


@app.route('/change_user', methods=['GET', 'POST'])
def change_user():
    if 'username' in session:
        return render_template('change_user.html',
                               i=find_document(users, {'_id': bson.ObjectId(request.form['change_button'])}, False,
                                               True))


@app.route('/change', methods=['POST'])
def change():
    if 'username' in session:
        if request.method == 'POST':
            if request.form['role'] == 1:
                update_document(users, {'_id': bson.ObjectId(request.form['button_for_change'])},
                                {'last_name': request.form['last_name'],
                                 'first_name': request.form['first_name'],
                                 'middle_name': request.form['middle_name'], 'uid': request.form['uid'],
                                 'role': request.form['role'],
                                 'password': generate_password_hash(request.form['password']),
                                 'modified_date': datetime.datetime.now()})
            else:
                update_document(users, {'_id': bson.ObjectId(request.form['button_for_change'])},
                                {'last_name': request.form['last_name'],
                                 'first_name': request.form['first_name'],
                                 'middle_name': request.form['middle_name'], 'uid': request.form['uid'],
                                 'role': request.form['role'],
                                 'modified_date': datetime.datetime.now()})
                return redirect('/')
            log = {'action': 'modified', 'last_name': request.form['last_name'],
                   'first_name': request.form['first_name'],
                   'middle_name': request.form['middle_name'], 'uid': request.form['uid'],
                   'date': datetime.datetime.now()}
            insert_document(logs, log)
    else:
        return redirect(url_for('login'))


@app.route('/delete_user', methods=['POST'])
def delete_user():
    if 'username' in session:
        if request.method == 'POST':
            cash = users.find_one({'_id': bson.ObjectId(request.form['delete_button'])})
            delete_document(users, {'_id': bson.ObjectId(request.form['delete_button'])})
            insert_document(deleted_users, cash)
            log = update_document(users, {'_id': bson.ObjectId(request.form['delete_button'])},
                                  {'action': 'deleted', 'date': datetime.datetime.now()})
            insert_document(logs, log)
            return redirect('/')
    else:
        return redirect(url_for('login'))


@app.route('/logs', methods=['GET', 'POST'])
def logs_view():
    if 'username' in session:
        if request.method == 'GET':
            row = find_document(logs)
            return render_template('logs.html', rows=row)


# @app.route('/check', methods=['POST'])
# def check():
#     if request.method == 'POST':
#


@app.route('/logout', methods=['POST'])
def logout():
    if 'username' in session:
        if request.method == 'POST':
            session.pop('username', None)
            return redirect(url_for('login'))
