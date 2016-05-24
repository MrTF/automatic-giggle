#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" main.py

Basic register and login website using Flask

Copyright (c) 2016 Fatih Tümen

This work is licensed under a 
    GNU Affero General Public License v3.0
"""

import sqlite3
from contextlib import contextmanager
from flask import Flask

app = Flask(__name__)
DBFILENAME = "giggle.db"
db = None


class Singleton:
    """ Abstract singleton restricting multiple instance of DBHandler
    """
    def __init__(self, dec_cls):
        self._dec_cls = dec_cls

    def instantiate(self):
        try:
            self._instance
        except AttributeError:
            self._instance = self._dec_cls()
            return self._instance


@Singleton
class DBHandler(object):
    """ SQLite database handler
    """
    def __init__(self, filename):
        self.filename = filename

    @contextmanager
    def _connect(self):
        """ Keeps an open DB connection to be safely closed upon __exit__"""
        conn = sqlite3.connect(self.filename)
        try:
            yield conn
        finally:
            self._closedb(conn)

    def _close(self):
        """ Safely closes the DB connection"""
        try:
            self.conn.close()
        except Exception as e:
            print("Failed to close DB: {1}".format(e))

    def query(self, sql, *args):
        pass


@app.route('/register', methods=['GET', 'POST'])
def register():
    """ Sign up new members"""
    pass


@app.route('/login', methods=['GET', 'POST'])
def login():
    """ Sign in existing members"""
    pass


@app.route('/welcome')
def welcome():
    """ Greets the members """
    pass


@app.route('/logout')
def logout():
    """ Bid farewell to the member"""
    pass


if __name__ == '__main__':
    db = DBHandler(DBFILENAME)
    app.run()