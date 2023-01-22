from flask import Flask, render_template, request, make_response, redirect, send_file
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import markdown
from collections import deque
from passlib.hash import sha256_crypt
import sqlite3
import os, requests
import bleach
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import time
import re 

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

app.secret_key = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"

DATABASE = "./sqlite3.db"
MARKDOWN_ATTRS = {'*': ['id'], 'img': ['src', 'alt', 'title'], 'a': ['href', 'alt', 'title']}
MARKDOWN_TAGS = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'strong', 'em', 'p', 'blockquote', 'ol', 'li', 'ul', 'a', 'img', 'br']

class User(UserMixin):
    pass

@login_manager.user_loader
def user_loader(username):
    if username is None:
        return None

    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(f"SELECT username, password FROM user WHERE username = '{username}'")
    row = sql.fetchone()
    try:
        username, password = row
    except:
        return None

    user = User()
    user.id = username
    user.password = password
    return user


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = user_loader(username)
    return user

recent_users = deque(maxlen=3)

@app.route("/", methods=["GET","POST"])
def login():
    
    global LOGIN_ATTEMPTS
    LOGIN_ATTEMPTS = int(0)   
    if request.method == "GET":
        return render_template("index.html")
    if request.method == "POST":
        username = request.form.get("username")
        username = bleach.clean(username)
        
        password = request.form.get("password")
        password = bleach.clean(password)
        
        user = user_loader(username)
        time.sleep(2)
        if LOGIN_ATTEMPTS >= 10:
            time.sleep(300)
            LOGIN_ATTEMPTS = 0
        if user is None:
            LOGIN_ATTEMPTS = LOGIN_ATTEMPTS + 1
            return "Nieprawidłowy login lub hasło", 401
        if sha256_crypt.verify(password, user.password):
            strength = check_strength(password)
            login_user(user)
            LOGIN_ATTEMPTS = 0
            if strength == True:
                return redirect('/hello')
            else:
                return redirect('/weakpasswordreminder')
        else:
            LOGIN_ATTEMPTS = LOGIN_ATTEMPTS + 1
            return "Nieprawidłowy login lub hasło", 401

@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")

@app.route("/hello", methods=['GET'])
@login_required
def hello():
    if request.method == 'GET':
        username = current_user.id
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute(f"SELECT id FROM notes WHERE username == '{username}' OR isshared == 'yes'")
        notes = sql.fetchall()

        return render_template("hello.html", username=username, notes=notes)
    
LAST_RENDERED_ID = int(0)

@app.route("/render", methods=['POST'])
@login_required
def render():
    md = request.form.get("markdown")
    rendered = bleach.clean(markdown.markdown(md), MARKDOWN_TAGS, MARKDOWN_ATTRS)
    username = current_user.id
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(f"INSERT INTO notes (username, note, isshared, isencrypted) VALUES ('{username}', '{rendered}', 'no', 'no')")
    db.commit()
    return render_template("markdown.html", rendered=rendered)

@app.route("/renderpublic", methods=['POST'])
@login_required
def renderpublic():
    md = request.form.get("markdown")
    rendered = bleach.clean(markdown.markdown(md), MARKDOWN_TAGS, MARKDOWN_ATTRS)
    username = current_user.id
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(f"INSERT INTO notes (username, note, isshared, isencrypted) VALUES ('{username}', '{rendered}', 'yes', 'no')")
    db.commit()
    return render_template("markdown.html", rendered=rendered)

@app.route("/menu", methods=['POST'])
@login_required
def encryption():
    global passwordenc
    passwordenc = request.form.get("password")
    raw = request.form.get("render")
    username = current_user.id
    global encrypted
    encrypted = encrypt(raw, passwordenc)
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    #print(LAST_RENDERED_ID)
    sql.execute(f"UPDATE notes SET note = 'This note was hidden by its creator' WHERE id == '{LAST_RENDERED_ID}'")
    sql.execute(f"UPDATE notes SET isencrypted = 'yes' WHERE id == '{LAST_RENDERED_ID}'")
    db.commit()
    sql.execute(f"SELECT id FROM notes WHERE username == '{username}' OR isshared == 'yes'")
    notes = sql.fetchall()
    return render_template("hello.html", username=username, notes=notes)

@app.route("/menutwo", methods=['POST'])
@login_required
def decryption():
    password = request.form.get("password")
    if password != passwordenc:
        return "Wrong password!", 403
    username = current_user.id
    decrypted = decrypt(encrypted, password)
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(f"UPDATE notes SET note = '{decrypted}' WHERE id == '{LAST_RENDERED_ID}'")
    sql.execute(f"UPDATE notes SET isencrypted = 'no' WHERE id == '{LAST_RENDERED_ID}'")
    db.commit()
    sql.execute(f"SELECT id FROM notes WHERE username == '{username}' OR isshared == 'yes'")
    notes = sql.fetchall()
    return render_template("hello.html", username=username, notes=notes)

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def encrypt(raw, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    raw = pad(raw)
    raw = raw.encode("utf8")
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))
 
 
def decrypt(enc, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]).decode("utf-8"))

@app.route("/render/<rendered_id>")
@login_required
def render_old(rendered_id):
    global LAST_RENDERED_ID
    LAST_RENDERED_ID = rendered_id
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(f"SELECT username, isshared, isencrypted, note FROM notes WHERE id == '{rendered_id}'")
    try:
        username, isshared, isencrypted, rendered = sql.fetchone()
        if username == current_user.id and isencrypted == 'no':
            return render_template("encrypt.html", rendered=rendered)
        if username == current_user.id and isencrypted == 'yes':
            return render_template("decrypt.html", rendered=rendered)
        if isshared == 'yes':
            return render_template("markdown.html", rendered=rendered)
        else:
            return "No access to note", 403
    except:
        return "Note not found", 404
    

@app.route("/user/register", methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template("register.html")
    if request.method == 'POST':
        username_check = request.form.get("username")
        pattern = re.compile("[A-Za-z0-9]+")
        if pattern.fullmatch(username_check) is None:
            return "Username can only contain letters from A-Z, a-z and numbers 0-9", 403
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()

        username = request.form.get('username')
        username = bleach.clean(username)
        password = request.form.get('password')
        password = bleach.clean(password)
        
        strength = check_strength(password)

        sql.execute(f"INSERT INTO user (username, password) VALUES ('{username}', '{sha256_crypt.hash(password)}');")

        db.commit()
        if strength == True:
            return redirect('/')
        else:
            username = current_user.id
            
            return redirect('/weakpasswordunregisteredreminder')
        
@app.route("/weakpasswordreminder")
def weakpassword():
    return render_template("weakpasswordregistered.html")

@app.route("/weakpasswordunregisteredreminder")
def weakpasswordunregistered():
    return render_template("weakpasswordunregistered.html")

@app.route("/change", methods=['POST'])
@login_required
def change():
    return render_template("changepassword.html")

@app.route("/changepassword", methods=['POST'])
@login_required
def changepassword():
    password = request.form.get("password")
    username = current_user.id
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(f"UPDATE user SET password = '{sha256_crypt.hash(password)}' WHERE username == '{username}'")
    sql.execute(f"UPDATE notes SET isencrypted = 'no' WHERE id == '{LAST_RENDERED_ID}'")
    db.commit()
    return redirect('/hello')
    
def check_strength(string):
    unique_chars_num = len(set(string))
    lowercase_chars = 0
    uppercase_chars = 0
    number_chars = 0
    special_chars = 0
    for i in range(0, len(string)):  
        ch = string[i]
        if string[i].isalpha() and string[i].islower():
            lowercase_chars += 1
            continue
        if string[i].isalpha() and string[i].isupper():
            uppercase_chars += 1
            continue
        elif (string[i].isdigit()):
            number_chars += 1  
            continue
        else:
            special_chars += 1
            continue
    if lowercase_chars < 1 or uppercase_chars < 1 or number_chars < 1 or special_chars < 1 or unique_chars_num < 8:
        return False
    else:
        return True
    
    

if __name__ == "__main__":
    print("[*] Init database!")
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute("DROP TABLE IF EXISTS user;")
    sql.execute("CREATE TABLE user (username VARCHAR(32), password VARCHAR(128));")
    sql.execute("DELETE FROM user;")
    sql.execute("INSERT INTO user (username, password) VALUES ('john', '$5$rounds=535000$AO6WA6YC49CefLFE$dsxygCJDnLn5QNH/V8OBr1/aEjj22ls5zel8gUh4fw9');")
    sql.execute("INSERT INTO user (username, password) VALUES ('bob', '$5$rounds=535000$.ROSR8G85oGIbzaj$u653w8l1TjlIj4nQkkt3sMYRF7NAhUJ/ZMTdSPyH737');")

    sql.execute("DROP TABLE IF EXISTS notes;")
    sql.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, username VARCHAR(32), note VARCHAR(256), isshared VARCHAR(256), isencrypted VARCHAR(256));")
    sql.execute("DELETE FROM notes;")
    sql.execute("INSERT INTO notes (username, note, isshared, isencrypted, id) VALUES ('bob', 'To jest sekret!', 'no', 'no', 1);")
    db.commit()

    app.run("0.0.0.0", port=5000, ssl_context=('./SSL/server.crt', './SSL/server.key'))