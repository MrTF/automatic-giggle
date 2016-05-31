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
            conn.close()
        except Exception as e:
            print("Failed to close DB: {1}".format(e))

    def query(self, sql, args=()):
        """ Executes DB scripts sql with given arguments and return all results"""
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, args)
            return cursor.fetchall()


def query_db(sql, args=()):
    handler = DBHandler(filename=DBFILENAME)
    r = handler.query(sql, args)
    return r[0] if any(r) else None


def hash_password(pw):
    return generate_password_hash(pw)


def match_password(pw_hash, pw):
    return check_password_hash(pw_hash, pw)


def verify_username(username):
    """ Check whether username is available and meets the requirements"""
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
            msg = "Invalid e-email address!"
        elif not request.form['country']:
            msg = "Please choose you country!"
        else:
            # register new user meeting requirements
            sql = """INSERT INTO users ( username, password, email, country )
            values (?, ?, ?, ?)"""
            query_db(sql, request.form['username'],
                     hash_password(request.form['password']),
                     request.form['email'], request.form['country'])
            return redirect(url_for('login'))

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
        print(user)
        # check if user exist and password matches
        if user is None or not match_password(
                user['password'], request.form['password']):
            msg = "Invalid username or password"
        else:
            print(user)
            session['user_id'] = user['user_id']
            return redirect(url_for('welcome'))

    # unsuccessful login
    return render_template('login.html', error=msg)


@app.route('/welcome')
def welcome():
    """ Greets the members """
    msg = "Greetings!"
    return msg


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