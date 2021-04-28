import datetime

from . import app, users, deleted_users, logs, devices, startup_time
from flask import render_template, request, redirect, url_for, jsonify
from flask_login import login_required, login_user, logout_user
from .models import find_document, insert_document, update_document, delete_document, User
from werkzeug.security import check_password_hash, generate_password_hash
from bson import ObjectId
from requests.exceptions import HTTPError
import requests
import time


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
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


@app.route('/add_user', methods=['POST', 'GET'])
@login_required
def add_user():
    if request.method == 'POST':
        if request.form['role'] == '1':
            one = {'last_name': request.form['last_name'], 'first_name': request.form['first_name'],
                   'middle_name': request.form['middle_name'], 'gender': request.form['gender'],
                   'uid': request.form['uid'],
                   'password': generate_password_hash(request.form['password']),
                   'zone': request.form.getlist('checkbox'), 'role': request.form['role']}
            insert_document(users, one)
        else:
            one = {'last_name': request.form['last_name'], 'first_name': request.form['first_name'],
                   'middle_name': request.form['middle_name'], 'gender': request.form['gender'],
                   'uid': request.form['uid'],
                   'zone': request.form.getlist('checkbox'),
                   'role': request.form['role']}
            insert_document(users, one)
        insert_document(logs, {'last_name': request.form['last_name'], 'first_name': request.form['first_name'],
                               'middle_name': request.form['middle_name'], 'gender': request.form['gender'],
                               'uid': request.form['uid'], 'zone': request.form.getlist('checkbox'),
                               'role': request.form['role'],
                               'action': 'Добавлен',
                               'date': '{:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now())})
    return redirect('/')


@app.route('/device', methods=['GET'])
@login_required
def device():
    if request.method == 'GET':
        return render_template('device.html')


@app.route('/add_device', methods=['POST'])
@login_required
def add_device():
    if request.method == 'POST':
        insert_document(devices, {'name': request.form['device_name'], 'ip': request.form['ip'],
                                  'port': request.form['port'], 'zone': request.form['zone']})
        insert_document(logs, {'device_name': request.form['device_name'], 'ip': request.form['ip'],
                               'port': request.form['port'], 'zone': request.form['zone'],
                               'action': 'Добавлен',
                               'date': '{:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now())})
        return redirect('/')


@app.route('/change_device/<searchable>', methods=['GET'])
@login_required
def change_device(searchable):
    return render_template('change_device.html', i=find_document(devices, {'_id': ObjectId(searchable)}, False, True))


@app.route('/device_change', methods=['POST'])
@login_required
def device_change():
    if request.method == 'POST':
        update_document(devices, {'name': request.form['device_name'], 'ip': request.form['ip'],
                                  'port': request.form['port'], 'zone': request.form['zone']})
        insert_document(logs, {'device_name': request.form['device_name'], 'ip': request.form['ip'],
                               'port': request.form['port'], 'zone': request.form['zone'],
                               'action': 'Изменен',
                               'date': '{:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now())})


@app.route('/device_delete', methods=['POST'])
@login_required
def device_delete():
    if request.method == 'POST':
        for line in request.form.getlist('delete_checkbox'):
            cash = find_document(devices, {'_id': ObjectId(line)}, False, True)
            delete_document(devices, {'_id': ObjectId(line)})
            insert_document(logs, {'device_name': cash['name'], 'ip': cash['ip'],
                                   'port': cash['port'], 'zone': cash['zone'],
                                   'action': 'Удален',
                                   'date': '{:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now())})
        return redirect('/device_monitoring')


@app.route('/change_user/<searchable>', methods=['GET', 'POST'])
@login_required
def change_user(searchable):
    return render_template('change_user.html',
                           i=find_document(users, {'_id': ObjectId(searchable)}, False,
                                           True))


@app.route('/change', methods=['POST'])
@login_required
def change():
    lst = []
    ip, zone, port = '', '', ''
    head = "http://"
    destination = "/response_check"
    send_device = find_document(devices)
    if request.method == 'POST':
        if request.form['role'] == '1':
            update_document(users, {'_id': ObjectId(request.form['button_for_change'])},
                            {'last_name': request.form['last_name'],
                             'first_name': request.form['first_name'],
                             'middle_name': request.form['middle_name'], 'gender': request.form['gender'],
                             'uid': request.form['uid'],
                             'role': request.form['role'], 'zone': request.form.getlist('checkbox'),
                             'password': generate_password_hash(request.form['password'])})
        else:
            update_document(users, {'_id': ObjectId(request.form['button_for_change'])},
                            {'last_name': request.form['last_name'],
                             'first_name': request.form['first_name'],
                             'middle_name': request.form['middle_name'], 'uid': request.form['uid'],
                             'gender': request.form['gender'],
                             'role': request.form['role'], 'zone': request.form.getlist('checkbox')})

    insert_document(logs,
                    {'last_name': request.form['last_name'],
                     'first_name': request.form['first_name'],
                     'middle_name': request.form['middle_name'], 'uid': request.form['uid'],
                     'role': request.form['role'], 'zone': request.form.getlist('checkbox'),
                     'action': 'Изменен',
                     'date': '{:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now())})
    for i in send_device:
        for key, value in i.items():
            if key == 'ip':
                ip = value
            if key == 'port':
                port = value
            if key == 'zone':
                zone = value
        try:
            requests.get(head + ip + ":" + port + destination, timeout=0.01)
        except HTTPError:
            pass
        except Exception:
            pass
        else:
            if zone in request.form.getlist('checkbox'):
                lst.append({'_id': (request.form['button_for_change']),
                            'last_name': request.form['last_name'], 'first_name': request.form['first_name'],
                            'middle_name': request.form['middle_name'], 'uid': request.form['uid']})
                post = requests.post(head + ip + ":" + port + '/get_documents', json=lst)
                post = requests.post(head + ip + ":" + port + '/receive_change', json=lst)
            else:
                post = requests.post(head + ip + ":" + port + '/receive_delete', json=[request.form['button_for_change']])

    return redirect('/')


@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    ip = ""
    head = "http://"
    destination = "/response_check"
    if request.method == 'POST':
        for line in request.form.getlist('delete_checkbox'):
            cash = find_document(users, {'_id': ObjectId(line)}, False, True)
            delete_document(users, {'_id': ObjectId(line)})
            insert_document(logs, {'last_name': cash['last_name'], 'first_name': cash['first_name'],
                                   'middle_name': cash['middle_name'], 'uid': cash['uid'], 'role': cash['role'],
                                   'action': 'Удален',
                                   'date': '{:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now())})
            insert_document(deleted_users, cash)
        hosts = find_document(devices)
        for i in hosts:
            for key, value in i.items():
                if key == 'ip':
                    ip = value
                if key == 'port':
                    port = value
                try:
                    response = requests.get(head + ip + ':' + port + destination, timeout=0.01)
                except HTTPError:
                    pass
                except Exception:
                    pass
                else:
                    post = requests.post(head + ip + ":" + port + '/receive_delete',
                                         json=request.form.getlist('delete_checkbox'))
        return redirect('/')


@app.route('/logs', methods=['GET', 'POST'])
@login_required
def logs_view():
    if request.method == 'GET':
        row = find_document(logs)
        return render_template('logs.html', rows=row)


@app.route('/receive_logs', methods=['GET'])
@login_required
def receive_logs():
    ip = ""
    head = "http://"
    destination = "/response_check"
    hosts = find_document(devices)
    for i in hosts:
        for key, value in i.items():
            if key == 'ip':
                ip = value
            if key == 'port':
                port = value
            try:
                response = requests.get(head + ip + ':' + port + destination, timeout=0.01)
            except HTTPError:
                pass
            except Exception:
                pass
            else:
                log = requests.post(head + ip + ':' + port + '/send_log', json='send_logs')
                for i in log.json():
                    insert_document(logs, i)
                return redirect('/logs')


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


@app.route('/recovery', methods=['GET'])
@login_required
def recovery():
    if request.method == 'GET':
        return render_template('recovery.html', rows=find_document(deleted_users))


@app.route('/recovery_user', methods=['POST'])
@login_required
def recovery_user():
    if request.method == 'POST':
        for line in request.form.getlist('recovery_checkbox'):
            result = find_document(deleted_users, {'_id': ObjectId(line)}, False, True)
            insert_document(users, result)
            insert_document(logs, {'last_name': result['last_name'],
                                   'first_name': result['first_name'],
                                   'middle_name': result['middle_name'], 'role': result['role'], 'zone': result['zone'],
                                   'action': 'Восстановлен',
                                   'date': '{:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now())})
            delete_document(deleted_users, result)
        return redirect('/send_document')


@app.route('/device_monitoring', methods=['GET', 'POST'])
@login_required
def device_monitoring():
    ip = ""
    timer, status = {}, {}
    head = "http://"
    destination = "/response_check"
    hosts = find_document(devices)
    for i in hosts:
        for key, value in i.items():
            if key == 'ip':
                ip = value
            if key == 'port':
                port = value
            try:
                response = requests.get(head + ip + ':' + port + destination, timeout=0.01)
            except HTTPError:
                status[ip] = 'Не работает'
                timer[ip] = '0:00:00'
            except Exception:
                status[ip] = 'Не работает'
                timer[ip] = '0:00:00'
            else:
                status[ip] = 'Работает'
                timer[ip] = response.text
    return render_template('device_monitoring.html', row=hosts, state=status, timer=timer)


@app.route('/response_check', methods=['GET'])
def response_check():
    if request.method == 'GET':
        timer = str(datetime.timedelta(seconds=time.time() - startup_time)).split('.')
        return timer[0]


@app.route('/send_document', methods=['GET'])
def send_document():
    lst = []
    ip, zone = '', ''
    head = "http://"
    destination = "/response_check"
    send_user = find_document(users)
    send_device = find_document(devices)
    for i in send_device:
        for key, value in i.items():
            if key == 'ip':
                ip = value
            if key == 'port':
                port = value
            if key == 'zone':
                zone = value
        try:
            requests.get(head + ip + ":" + port + destination, timeout=0.01)
        except HTTPError:
            pass
        except Exception:
            pass
        else:
            for j in send_user:
                for k, v in j.items():
                    if k == 'zone':
                        for z in v:
                            if z == zone:
                                lst.append({'_id': str(j['_id']),
                                            'last_name': j['last_name'], 'first_name': j['first_name'],
                                            'middle_name': j['middle_name'], 'uid': j['uid']})

        post = requests.post('http://' + ip + ":" + port + '/get_documents', json=lst)
    lst = []
    return redirect('/')


@app.after_request
def redirect_singin(response):
    if response.status_code == 401:
        return redirect(url_for('login') + '?next=' + request.url)
    return response
