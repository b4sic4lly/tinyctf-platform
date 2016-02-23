#!/usr/bin/env python

"""server.py -- the main flask server module"""

import dataset
import json
import random
import time
import re
import hashlib
import os

from base64 import b64decode
from functools import wraps

from flask import Flask
from flask import jsonify
from flask import make_response
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask import abort

app = Flask(__name__, static_folder='static', static_url_path='')

db = None
lang = None
config = None
username_regex = None
start = None 
end = None

def is_valid_username(u):
    """Ensures that the username matches username_regex"""
    if(username_regex.match(u)):
        return True
    return False

def login_required(f):
    """Ensures that an user is logged in"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('error', msg='login_required'))
        return f(*args, **kwargs)
    return decorated_function

def before_end(f):
    """Ensures that actions can only be done before the CTF is over"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        cur_time = int(time.time())
        if cur_time >= end:
            return redirect(url_for('error', msg='ctf_over'))
        return f(*args, **kwargs)
    return decorated_function

def after_start(f):
    """Ensures that actions can only be done after the CTF has started"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        cur_time = int(time.time())
        if cur_time < start:
            return redirect(url_for('error', msg='ctf_not_started'))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_ctftime():
    st = time.strftime("%Y-%m-%d, %H:%M:%S (%Z)",time.localtime(start))
    ed = time.strftime("%Y-%m-%d, %H:%M:%S (%Z)",time.localtime(end))
    return dict(ctf_start=st, ctf_stop=ed)


def get_user():
    """Looks up the current user in the database"""

    login = 'user_id' in session    
    if login:
        return (True, db['users'].find_one(id=session['user_id']))

    return (False, None)

def get_task(category, score):
    """Finds a task with a given category and score"""

    task = db.query('''select t.* from tasks t, categories c, cat_task ct 
        where t.id = ct.task_id and c.id = ct.cat_id 
        and t.score=:score and lower(c.short_name)=:cat''',
        score=score, cat=category)
    return list(task)[0]

def get_flags():
    """Returns the flags of the current user"""

    flags = db.query('''select f.task_id from flags f 
        where f.user_id = :user_id''',
        user_id=session['user_id'])
    return [f['task_id'] for f in list(flags)]

@app.route('/error/<msg>')    
def error(msg):
    """Displays an error message"""

    if msg in lang['error']:
        message = lang['error'][msg]
    else:
        message = lang['error']['unknown']

    login, user = get_user()

    render = render_template('frame.html', lang=lang, page='error.html', 
        message=message, login=login, user=user)
    return make_response(render)

def session_login(username):
    """Initializes the session with the current user's id"""
    user = db['users'].find_one(username=username)
    session['user_id'] = user['id']

@app.route('/login', methods = ['POST'])
def login():
    """Attempts to log the user in"""

    from werkzeug.security import check_password_hash

    username = request.form['user']
    password = request.form['password']

    user = db['users'].find_one(username=username)
    if user is None:
        return redirect('/error/invalid_credentials')

    if check_password_hash(user['password'], password):
        session_login(username)
        return redirect('/tasks')

    return redirect('/error/invalid_credentials')

@app.route('/register')
@before_end
def register():
    """Displays the register form"""

    # Render template
    render = render_template('frame.html', lang=lang, 
        page='register.html', login=False)
    return make_response(render) 

@app.route('/register/submit', methods = ['POST'])
@before_end
def register_submit():
    """Attempts to register a new user"""

    from werkzeug.security import generate_password_hash

    username = request.form['user']
    password = request.form['password']

    if not username:
        return redirect('/error/empty_user')

    if not is_valid_username(username):
        return redirect('/error/invalid_user')

    user_found = db['users'].find_one(username=username)
    if user_found:
        return redirect('/error/already_registered')
            
    new_user = dict(hidden=0, username=username, 
        password=generate_password_hash(password))
    db['users'].insert(new_user)

    # Set up the user id for this session
    session_login(username)

    return redirect('/tasks')

@app.route('/tasks')
@login_required
@after_start
def tasks():
    """Displays all the tasks in a grid"""

    login, user = get_user()
    flags = get_flags()

    categories = db['categories']

    tasks = db.query('''select c.id as cat_id, t.id as id, c.short_name, 
        t.score, t.row from categories c, tasks t, cat_task c_t 
        where c.id = c_t.cat_id and t.id = c_t.task_id''')
    tasks = list(tasks)

    grid = []
    # Find the max row number
    max_row = max(t['row'] for t in tasks)

    for row in range(max_row + 1):

        row_tasks = []
        for cat in categories:

            # Find the task with the correct row
            for task in tasks:
                if task['row'] == row and task['cat_id'] == cat['id']:
                    break
            else:
                task = None

            row_tasks.append(task)

        grid.append(row_tasks)

    # Render template
    render = render_template('frame.html', lang=lang, page='tasks.html', 
        login=login, user=user, categories=categories, grid=grid, 
        flags=flags)
    return make_response(render) 

@app.route('/tasks/<category>/<score>')
@login_required
@after_start
def task(category, score):
    """Displays a task with a given category and score"""

    login, user = get_user()

    task = get_task(category, score)
    if not task:
        return redirect('/error/task_not_found')

    flags = get_flags()
    task_done = task['id'] in flags

    solutions = db['flags'].find(task_id=task['id'])
    solutions = len(list(solutions))

    # Render template
    render = render_template('frame.html', lang=lang, page='task.html', 
        task_done=task_done, login=login, solutions=solutions,
        user=user, category=category, task=task, score=score)
    return make_response(render)

@app.route('/task/submit', methods = ['POST'])
@login_required
@before_end
@after_start
def submit():
    """Handles the submission of flags"""
    category = request.form['category']
    score = request.form['score']
    flag = request.form['flag']

    login, user = get_user()

    task = get_task(category, score)
    flags = get_flags()
    task_done = task['id'] in flags

    result = {'success': False, 'csrf': generate_csrf_token() }

    if not task_done and task['flag'] == b64decode(flag):

        timestamp = int(time.time() * 1000)

        # Insert flag
        new_flag = dict(task_id=task['id'], user_id=session['user_id'], 
            score=score, timestamp=timestamp)
        db['flags'].insert(new_flag)

        result['success'] = True

    return jsonify(result)

@app.route('/scoreboard')
def scoreboard():
    """Displays the scoreboard"""

    login, user = get_user()
    scores = db.query('''select u.username, ifnull(sum(f.score), 0) as score, 
        max(timestamp) as last_submit from users u left join flags f 
        on u.id = f.user_id where u.hidden = 0 group by u.username 
        order by score desc, last_submit asc''')

    scores = list(scores)

    # Render template
    render = render_template('frame.html', lang=lang, page='scoreboard.html', 
        login=login, user=user, scores=scores)
    return make_response(render) 

@app.route("/scoreboard.json")
def scoreboard_json():
    """Displays data for ctftime.org in json format"""
    scores = db.query('''select u.username as team, ifnull(sum(f.score), 0) as score, ifnull(max(timestamp), 0) as lastAccept from users
                        u left join flags f on u.id = f.user_id where u.hidden = 0 group by u.username
                        order by score desc, lastAccept asc''')
    scores = list(scores)
    for i, s in enumerate(scores):
        s['pos'] = i + 1
        
    data = map(dict,scores) 
    return jsonify({'standings':data})

@app.route('/about')
def about():
    """Displays the about menu"""

    login, user = get_user()

    # Render template
    render = render_template('frame.html', lang=lang, page='about.html', 
        login=login, user=user)
    return make_response(render) 

@app.route('/logout')
@login_required
def logout():
    """Logs the current user out"""

    del session['user_id']
    return redirect('/')

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            abort(400)

def some_random_string():
    return hashlib.sha256(os.urandom(16)).hexdigest()

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = some_random_string()
    return session['_csrf_token']

@app.route('/')
def index():
    """Displays the main page"""

    login, user = get_user()

    # Render template
    render = render_template('frame.html', lang=lang, 
        page='main.html', login=login, user=user)
    return make_response(render)

if __name__ == '__main__':
    """Initializes the database and sets up the language"""

    # Load config
    config_str = open('config.json', 'rb').read()
    config = json.loads(config_str)

    app.secret_key = config['secret_key']

    # Load language
    lang_str = open(config['language_file'], 'rb').read()
    lang = json.loads(lang_str)

    # Only a single language is supported for now
    lang = lang[config['language']]

    # Connect to database
    db = dataset.connect(config['db'])

    # Compile regex for usernames
    username_regex = re.compile(config['username_regex'])

    # Setup the flags table at first execution
    if 'flags' not in db.tables:
        db.query('''create table flags (
            task_id INTEGER, 
            user_id INTEGER, 
            score INTEGER, 
            timestamp BIGINT, 
            PRIMARY KEY (task_id, user_id))''')

    app.jinja_env.globals['csrf_token'] = generate_csrf_token

    start = config['start']
    end = config['end']

    # Start web server
    app.run(host=config['host'], port=config['port'], 
        debug=config['debug'], threaded=True)

