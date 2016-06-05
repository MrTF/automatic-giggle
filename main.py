#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" main.py

Basic register and login website using Flask

Copyright (c) 2016 Fatih Tümen

This work is licensed under a
    GNU Affero General Public License v3.0
"""

import sqlite3
import re
from contextlib import contextmanager
from werkzeug import generate_password_hash, check_password_hash
from flask import Flask, request, session, redirect, url_for, render_template, g
from flask import flash

app = Flask(__name__)
SECRET_KEY = "secret-to-a-giggle"
app.secret_key = SECRET_KEY
DBFILENAME = "giggle.db"
db = None


class Singleton(type):
    """ Abstract singleton restricting multiple instance of DBHandler
    """
    _instances = {}

    def __call__(cls, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(**kwargs)
        else:
            cls._instances.__init__(**kwargs)

        return cls._instances[cls]

    '''
    def __init__(self, dec_cls):
        self._dec_cls = dec_cls

    def instantiate(*args):
        try:
            self._instance
        except AttributeError:
            self._instance = self._dec_cls()
            return self._instance
    '''


class DBHandler(metaclass=Singleton):
    """ SQLite database handler
    """
    def __init__(self, **kwargs):
        self.filename = kwargs['filename']
        self._init_db()

    def _init_db(self):
        self.query("""
        CREATE TABLE IF NOT EXISTS users (
            user_id integer primary key autoincrement,
            username text not_null,
            password text not null,
            email text not null,
            country text not null )""")

    @contextmanager
    def _connect(self):
        """ Keeps an open DB connection to be safely closed upon __exit__
            Do not call directly
        """
        conn = sqlite3.connect(self.filename)
        try:
            yield conn
        finally:
            self._close(conn)

    def _close(self, conn):
        """ Safely closes the DB connection upon exit.
            Do not call directly.
        """
        try:
            conn.commit()
            conn.close()
        except Exception as e:
            print("Failed to close DB: {1}".format(e))

    def query(self, sql, args=()):
        """ Executes DB scripts sql with given arguments and return all results"""
        r = None
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, args)
            r = cursor.fetchall()

        return r


def query_db(sql, args=()):
    if app.debug:
        print(args)
    handler = DBHandler(filename=DBFILENAME)
    r = handler.query(sql, args)
    return r[0] if any(r) else None


def build_user_dict(user):
    """ Convert DB user entry info python dict """
    u = {}
    u['user_id']    = user[0]
    u['username']   = user[1]
    u['password']   = user[2]
    u['email']      = user[3]
    u['country]']   = user[4]

    return u


def hash_password(pw):
    return generate_password_hash(pw)


def match_passwords(pw_hash, pw):
    return check_password_hash(pw_hash, pw)


def verify_username(username):
    """ Check whether username is available and meets the requirements"""
    # TODO: min nr of letters
    rex = r"(^[a-zA-Z0-9_.+-]{3,16}$)"
    if not re.match(rex, username):
        return False
    if query_db("""SELECT username FROM users WHERE username=?""", [username,]):
        return False

    return True


def verify_password(password):
    """ Check if password meets the requirements"""
    rex = r"(^[a-zA-Z0-9_.+-]{6,16}$)"
    re.match(rex, password)
    return True


def confirm_password(password0, password1):
    """ Check whether two passwords matches"""
    return password0 == password1


def verify_email(email):
    rex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    r = re.match(rex, email)
    return False if not r else True


@app.route('/register', methods=['GET', 'POST'])
def register():
    """ Sign up new members"""
    msg = None
    if request.method == 'POST':
        # check required fields
        # username
        # password
        # email
        # country
        if not verify_username(request.form['username']):
            msg = "Invalid username!"
        elif not verify_password(request.form['password']):
            msg = "Insecure password!"
        elif not confirm_password(
                request.form['password'], request.form['password1']):
            msg = "Passwords do not match!"
        elif not verify_email(request.form['email']):
            msg = "Invalid e-mail address!"
        # TODO: use ajax for country drowdown
        elif not request.form['country']:
            msg = "Please choose you country!"
        else:
            # register new user meeting requirements
            sql = """INSERT INTO users ( username, password, email, country )
            values (?, ?, ?, ?)"""
            args = [request.form['username'],
                     hash_password(request.form['password']),
                     request.form['email'], request.form['country']]
            r = query_db(sql, args)
            msg = "You have been registered successfully!"
            flash(msg)
            return redirect(url_for('login'))

    if msg is not None: flash(msg)
    return render_template('register.html', error=msg)


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    """ Sign in existing members"""
    # TODO: keep alive
    msg = "Members only!"

    if request.method == 'POST':
        user = query_db("""SELECT * FROM users WHERE username = ?""",
                     [request.form['username']])

        if app.debug:
            print(user)
            print(request.form)
        # check if user exist
        if user is not None:
            user = build_user_dict(user)
        else:
            msg = "Invalid username or password!"
            flash(msg)
            return render_template('login.html', error=msg)

        # check password
        if not match_passwords(user['password'], request.form['password']):
            msg = "Invalid username or password!"
            flash(msg)
            return render_template('login.html', error=msg)
        else:
            session['user_id'] = user['user_id']
            g.user = user
            return redirect(url_for('welcome'))

    return render_template('login.html', error=msg)


@app.before_request
def before_request():
    """ Before every page request """
    # Attach user info
    g.user = None
    if 'user_id' in session:
        user = query_db('SELECT * FROM users WHERE user_id = ?', [session['user_id']])
        if user is not None:
            user = build_user_dict(user)

        g.user = user
        print(g.user)


@app.route('/welcome')
def welcome():
    """ Greets the members """

    return render_template('welcome.html')


@app.route('/logout')
def logout():
    """ Bid farewell to the member"""
    msg = "You're leaving so soon? Farewell!"
    flash(msg)
    session.pop('user_id', None)

    return redirect(url_for('login'))


if __name__ == '__main__':
    db = DBHandler(filename=DBFILENAME)
    app.debug = True
    app.run()