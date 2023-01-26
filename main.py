from flask import Flask, render_template, request, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import markdown
from passlib.hash import sha256_crypt
import sqlite3
from bleach import clean
from utils import *

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1/second"],
    storage_uri="memory://",
)

app.secret_key = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"

database_ref = "./sqlite3.db"
sha256_rounds = 643346
pbkdf2_rounds = 1111111
allowed_tags = ['p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'strong', 'em', 'a', 'img']
allowed_attributes = {'a': ['href', 'title'], 'img': ['src', 'alt']}


class User(UserMixin):
    pass


@login_manager.user_loader
def user_loader(username):
    if username is None:
        return None

    db = sqlite3.connect(database_ref)
    sql = db.cursor()
    sql.execute("SELECT username, password_hashed FROM user WHERE username = ?", (username, ))
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


@app.route("/", methods=["GET"])
def login_form():
    return render_template("index.html")


@app.route("/", methods=["POST"])
@limiter.limit("5/minute", override_defaults=False)
@limiter.limit("50/hour", override_defaults=False)
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    user = user_loader(username)
    if user is None:
        delay()
        return "Bad login or password", 401
    if sha256_crypt.verify(password, user.password):
        login_user(user)
        return redirect('/profile')
    else:
        delay()
        return "Bad login or password", 401


@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")


@app.route("/register", methods=["GET"])
def register_form():
    return render_template("register.html")


@app.route("/register", methods=['POST'])
@limiter.limit("10/minute", override_defaults=False)
@limiter.limit("50/hour", override_defaults=False)
def register():
    db = sqlite3.connect(database_ref)
    sql = db.cursor()

    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    if confirm_password != password:
        return "Password must match confirmation password", 400

    validation_problem = verify_password_strength(password)
    if validation_problem is not None:
        return validation_problem, 400

    sql.execute("SELECT username FROM user WHERE username == ?", (username, ))
    if sql.fetchone() is not None:
        delay(5)
        return "Could not use provided username", 400

    salt = get_random_string(16)
    hashed = sha256_crypt.using(rounds=sha256_rounds, salt=salt).hash(password)

    sql.execute("INSERT INTO user (username, password_hashed) VALUES (?, ?);", (username, hashed))
    db.commit()

    return redirect('/')


@app.route("/profile", methods=['GET'])
@login_required
def profile():
    if request.method == 'GET':
        username = current_user.id

        db = sqlite3.connect(database_ref)
        sql = db.cursor()
        sql.execute("SELECT id FROM notes WHERE username == ?", (username, ))
        notes = sql.fetchall()

        return render_template("profile.html", username=username, notes=notes)

@app.route("/public_board", methods=['GET'])
@login_required
def public_board():
    if request.method == 'GET':

        db = sqlite3.connect(database_ref)
        sql = db.cursor()
        sql.execute("SELECT id, username FROM notes WHERE is_public = 1")
        notes = sql.fetchall()

        return render_template("public_board.html", notes=notes)

@app.route("/render", methods=['POST'])
@login_required
def render():

    is_public = request.form.get("is_public")
    if is_public is not None:
        is_public = 1
    else:
        is_public = 0

    encryption_password = request.form.get("encryption_password")
    if encryption_password is not None and encryption_password != "":
        is_encrypted = 1
    else:
        is_encrypted = 0

    rendered = request.form.get("markdown", "")
    if is_encrypted:
        rendered = encrypt(rendered, encryption_password)

    username = current_user.id

    db = sqlite3.connect(database_ref)
    sql = db.cursor()
    sql.execute("INSERT INTO notes (username, content, is_public, is_encrypted) VALUES (?, ?, ?, ?)", (username, rendered, is_public, is_encrypted))
    db.commit()

    return render_template("markdown.html", rendered=clean(markdown.markdown(rendered), allowed_tags, allowed_attributes), is_encrypted=is_encrypted, note_id=sql.lastrowid)


@app.route("/render/<rendered_id>", methods=['GET', 'POST'])
@login_required
@limiter.limit("5/minute", override_defaults=False)
def render_old(rendered_id):
    db = sqlite3.connect(database_ref)
    sql = db.cursor()
    sql.execute("SELECT username, content, is_public, is_encrypted FROM notes WHERE id == ?", (rendered_id, ))

    try:
        username, rendered, is_public, is_encrypted = sql.fetchone()
        if not is_public and username != current_user.id:
            return "Access to note forbidden", 403
        password = request.form.get("encryption_password")
        if request.method == 'POST' and password is not None and password != '':
            delay()
            rendered = decrypt(rendered, password)
        return render_template("markdown.html", rendered=clean(markdown.markdown(rendered), allowed_tags, allowed_attributes), is_encrypted=is_encrypted, note_id=rendered_id)
    except:
        return "Note not found", 404


if __name__ == "__main__":
    print("Initializing database . . .")
    db = sqlite3.connect(database_ref)
    sql = db.cursor()
    sql.execute("DROP TABLE IF EXISTS user;")
    sql.execute("CREATE TABLE user (username VARCHAR(32), password_hashed VARCHAR(128));")
    sql.execute("DELETE FROM user;")

    hashed = sha256_crypt.using(rounds=sha256_rounds, salt=get_random_string(16)).hash('bob')
    sql.execute("INSERT INTO user (username, password_hashed) VALUES ('bob', ?);", (hashed, ))

    sql.execute("DROP TABLE IF EXISTS notes;")
    sql.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, username VARCHAR(32), content BLOB, is_public BOOLEAN, is_encrypted BOOLEAN);")
    sql.execute("DELETE FROM notes;")

    rendered = encrypt('To jest sektetny (bo encrypted) sekret!', "czekoladowy przysmak")
    sql.execute("INSERT INTO notes (username, content, is_public, is_encrypted) VALUES ('bob', ?, 0, 1);", (rendered, ))
    rendered = encrypt('To jest public encrypted!', "kto wie ten wie ;)")
    sql.execute("INSERT INTO notes (username, content, is_public, is_encrypted) VALUES ('bob', ?, 1, 1);", (rendered, ))
    sql.execute("INSERT INTO notes (username, content, is_public, is_encrypted) VALUES ('bob', 'To jest zwykły sekret!', 0, 0);")
    sql.execute("INSERT INTO notes (username, content, is_public, is_encrypted) VALUES ('bob', 'To jest public!', 1, 0);")

    db.commit()
    """
    sql.execute("SELECT * FROM user")
    print(sql.fetchall())
    sql.execute("SELECT * FROM notes")
    print(sql.fetchall())
    """
    app.run("0.0.0.0", 5000)
