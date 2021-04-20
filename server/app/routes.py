import datetime

from . import app
from flask import render_template, request, flash, redirect, url_for
from flask_login import login_required, login_user, logout_user
from .models import find_document, insert_document, update_document, delete_document, User
from werkzeug.security import check_password_hash, generate_password_hash
from bson import ObjectId
from . import users, deleted_users, logs


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        row = (find_document(users, {'last_name': request.form['search']}, True))
        if not row:
            row = (find_document(users, {'first_name': request.form['search']}, True))
            if not row:
                row = (find_document(users, {'uid': request.form['search']}, True))
    else:
        row = find_document(users)
    return render_template('index.html', rows=row)


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
                            login_user(User(login=login))
                            next_page = request.args.get('next')
                            if next_page is None:
                                return redirect(url_for('index'))
                            else:
                                return redirect(next_page)
    return render_template('login.html', error=error)


@app.route('/users', methods=['GET'])
@login_required
def user():
    return render_template('users.html')


@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if request.method == 'POST':
        if request.form['role'] == '1':
            one = {'last_name': request.form['last_name'], 'first_name': request.form['first_name'],
                   'middle_name': request.form['middle_name'], 'uid': request.form['uid'],
                   'password': generate_password_hash(request.form['password']), 'role': request.form['role']}
            insert_document(users, one)
        else:
            one = {'last_name': request.form['last_name'], 'first_name': request.form['first_name'],
                   'middle_name': request.form['middle_name'], 'uid': request.form['uid'],
                   'role': request.form['role']}
            insert_document(users, one)
        insert_document(logs, {'last_name': request.form['last_name'], 'first_name': request.form['first_name'],
                               'middle_name': request.form['middle_name'], 'uid': request.form['uid'],
                               'action': 'Добавлен',
                               'date': '{:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now())})
    return redirect('/')


@app.route('/change_user', methods=['GET', 'POST'])
@login_required
def change_user():
    return render_template('change_user.html',
                           i=find_document(users, {'_id': ObjectId(request.form['change_button'])}, False,
                                           True))


@app.route('/change', methods=['POST'])
@login_required
def change():
    if request.method == 'POST':
        if request.form['role'] == '1':
            update_document(users, {'_id': ObjectId(request.form['button_for_change'])},
                            {'last_name': request.form['last_name'],
                             'first_name': request.form['first_name'],
                             'middle_name': request.form['middle_name'], 'uid': request.form['uid'],
                             'role': request.form['role'],
                             'password': generate_password_hash(request.form['password'])})
        else:
            update_document(users, {'_id': ObjectId(request.form['button_for_change'])},
                            {'last_name': request.form['last_name'],
                             'first_name': request.form['first_name'],
                             'middle_name': request.form['middle_name'], 'uid': request.form['uid'],
                             'role': request.form['role']})

    insert_document(logs,
                    {'last_name': request.form['last_name'],
                     'first_name': request.form['first_name'],
                     'middle_name': request.form['middle_name'], 'uid': request.form['uid'],
                     'action': 'Изменен',
                     'date': '{:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now())})
    return redirect('/')


@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    if request.method == 'POST':
        cash = find_document(users, {'_id': ObjectId(request.form['delete_button'])}, False, True)
        delete_document(users, {'_id': ObjectId(request.form['delete_button'])})
        insert_document(logs, {'last_name': cash['last_name'], 'first_name': cash['first_name'],
                               'middle_name': cash['middle_name'], 'uid': cash['uid'], 'action': 'Удален',
                               'date': '{:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now())})
        insert_document(deleted_users, cash)
        return redirect('/')


@app.route('/logs', methods=['GET', 'POST'])
@login_required
def logs_view():
    if request.method == 'GET':
        row = find_document(logs)
        return render_template('logs.html', rows=row)


@app.route('/check', methods=['POST'])
def check():
    uid = request.json
    check = find_document(users, {'uid': uid["rfid"]}, False, True)
    if check:
        insert_document(logs, {'last_name': check['last_name'], 'first_name': check['first_name'],
                               'middle_name': check['middle_name'], 'uid': check['uid'], 'entry_action': 'Разрешен',
                               'date': '{:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now())})
        return 'accept'
    else:
        insert_document(logs, {'uid': uid['rfid'], 'entry_action': 'Отказан',
                               'date': '{:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now())})
        return 'decline'


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    if request.method == 'POST':
        logout_user()
        return redirect(url_for('login'))


@app.route('/recovery', methods=['GET', 'POST'])
@login_required
def recovery():
    if request.method == 'GET':
        return render_template('recovery.html', rows=find_document(deleted_users))
    if request.method == 'POST':
        result = find_document(deleted_users, {'_id': ObjectId(request.form['recovery_button'])}, False, True)
        insert_document(users, result)
        insert_document(logs, {'last_name': result['last_name'], 'first_name': result['first_name'],
                               'middle_name': result['middle_name'], 'uid': result['uid'], 'action': 'Восстановлен',
                               'date': '{:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now())})
        delete_document(deleted_users, result)
        return render_template('recovery.html', rows=find_document(deleted_users))


@app.after_request
def redirect_singin(response):
    if response.status_code == 401:
        return redirect(url_for('login') + '?next=' + request.url)
    return response
