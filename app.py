from flask import Flask, request, render_template, session, redirect, url_for
from datetime import timedelta
import hashlib, os, time

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')

app.permanent_session_lifetime = timedelta(minutes=5)

login_attempts = {}
dummy_user = {'username': 'admin', 'password': 'password'}

@app.route('/', methods=['GET', 'POST'])
def home():
    session.modified = True
    if request.method == 'GET':
        session['sql_injection_vulnerable'] = False
        session['broken_auth_vulnerable'] = False
        if 'authenticated' in session and session['authenticated']:
            session['user_token'] = hashlib.sha256(os.urandom(1024)).hexdigest()
    return render_template('home.html')

@app.route('/submit', methods=['POST'])
def submit():
    result_message = ''
    message = ''
    pin = ''

    if 'message' in request.form and 'pin' in request.form:
        message = request.form['message']
        pin = request.form['pin']
        session['sql_injection_vulnerable'] = 'toggle_sql_injection' in request.form
        if (session['sql_injection_vulnerable'] or 
            not message.lower().startswith("' or") and not "1=1" in message):
            result_message = "SQL Injection attempt was NOT prevented!"
        else:
            result_message = "SQL Injection attempt was prevented!"
        session['result_type'] = 'SQL Injection'
   
    session['result_message'] = result_message
    session['message'] = message
    session['pin'] = pin

    return redirect(url_for('result'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    session.pop('user_token', None)
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        session['broken_auth_vulnerable'] = request.form.get('broken_auth', '') == 'on'
        
        if not session.get('broken_auth_vulnerable') and login_attempts.get(username, 0) >= 3:
            return render_template('login.html', error='Account is temporarily locked.')

        if username == dummy_user['username'] and password == dummy_user['password']:
            session['authenticated'] = True
            session['user_token'] = hashlib.sha256(os.urandom(1024)).hexdigest()
            login_attempts[username] = 0
            return redirect(url_for('home'))
        else:
            login_attempts[username] = login_attempts.get(username, 0) + 1
            session['authenticated'] = False
            return render_template('login.html', error='Invalid credentials.')

@app.route('/result')
def result():
    result_message = session.get('result_message', '')
    result_type = session.get('result_type', '')

    session.pop('result_message', None)
    session.pop('result_type', None)

    return render_template('result.html', result_message=result_message, result_type=result_type)

@app.route('/session_info')
def session_info():
    return render_template('session_info.html', session_token=session.get('user_token', 'No session token'),
                           login_attempts=login_attempts)

if __name__ == '__main__':
    app.run(debug=True)
