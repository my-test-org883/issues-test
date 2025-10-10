import sqlite3
import mysql.connector
import psycopg2
from flask import Flask, request

app = Flask(__name__)

# SQLi vulnerability #1: Direct string concatenation
@app.route('/users')
def get_users():
    user_id = request.args.get('id')
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()

    # Vulnerable: Direct string concatenation
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    results = cursor.fetchall()

    return str(results)

# SQLi vulnerability #2: String formatting
@app.route('/search')
def search_users():
    search_term = request.args.get('q')
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()

    # Vulnerable: String formatting
    query = "SELECT * FROM users WHERE name LIKE '%{}%'".format(search_term)
    cursor.execute(query)
    results = cursor.fetchall()

    return str(results)

# SQLi vulnerability #3: f-string injection
@app.route('/login')
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    conn = mysql.connector.connect(
        host='localhost',
        user='root',
        password='password',
        database='testdb'
    )
    cursor = conn.cursor()

    # Vulnerable: f-string injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    result = cursor.fetchone()

    return str(result)

# SQLi vulnerability #4: % formatting
@app.route('/admin')
def admin_panel():
    role = request.args.get('role')
    conn = psycopg2.connect(
        host="localhost",
        database="testdb",
        user="admin",
        password="secret"
    )
    cursor = conn.cursor()

    # Vulnerable: % string formatting
    query = "SELECT * FROM admin_users WHERE role = '%s'" % role
    cursor.execute(query)
    results = cursor.fetchall()

    return str(results)

if __name__ == '__main__':
    app.run(debug=True)