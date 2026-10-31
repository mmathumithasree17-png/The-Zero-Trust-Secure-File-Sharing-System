import os, io, json, base64, hashlib, secrets, sqlite3
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, session, redirect, url_for, render_template, flash, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_DIR, "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "encrypted_files")
DB_PATH = os.path.join(DATA_DIR, "app.db")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "development-only-change-me")
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL, public_key TEXT NOT NULL, private_key_enc TEXT NOT NULL,
          created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS files(
          id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL,
          original_name TEXT NOT NULL, stored_name TEXT NOT NULL, wrapped_key TEXT NOT NULL,
          nonce TEXT NOT NULL, sha256 TEXT NOT NULL, created_at TEXT NOT NULL,
          FOREIGN KEY(owner_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS shares(
          id INTEGER PRIMARY KEY AUTOINCREMENT, file_id INTEGER NOT NULL,
          recipient_id INTEGER NOT NULL, wrapped_key TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL, UNIQUE(file_id, recipient_id));
        CREATE TABLE IF NOT EXISTS audit(
          id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
          detail TEXT NOT NULL, timestamp TEXT NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
        """)
init_db()

def now():
    return datetime.now(timezone.utc).isoformat()

def b64(b): return base64.b64encode(b).decode()
def unb64(s): return base64.b64decode(s.encode())

def audit(actor, action, detail):
    with db() as con:
        last = con.execute("SELECT entry_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev = last["entry_hash"] if last else "GENESIS"
        timestamp = now()
        payload = f"{actor}|{action}|{detail}|{timestamp}|{prev}"
        digest = hashlib.sha256(payload.encode()).hexdigest()
        con.execute("INSERT INTO audit(actor,action,detail,timestamp,prev_hash,entry_hash) VALUES(?,?,?,?,?,?)",
                    (actor, action, detail, timestamp, prev, digest))

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def current_user():
    with db() as con:
        return con.execute("SELECT * FROM users WHERE id=?", (session.get("user_id"),)).fetchone()

@app.route("/")
def index():
    if "user_id" not in session: return redirect(url_for("login"))
    return redirect(url_for("dashboard"))

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        if len(username) < 3 or len(password) < 8:
            flash("Username must be 3+ characters and password at least 8 characters.")
            return render_template("register.html")
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        # Demo design: private key is encrypted at rest using a password-derived Fernet key.
        # Production systems should use a vetted KDF, stronger key custody, and client-side key storage.
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        salt = secrets.token_bytes(16)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        private_pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        encrypted_private = b64(salt) + "." + Fernet(key).encrypt(private_pem).decode()
        try:
            with db() as con:
                con.execute("INSERT INTO users(username,password_hash,public_key,private_key_enc,created_at) VALUES(?,?,?,?,?)",
                            (username, generate_password_hash(password), pub_pem, encrypted_private, now()))
            audit(username, "REGISTER", "account created")
            flash("Account created. Please sign in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That username already exists.")
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username, password = request.form.get("username","").strip(), request.form.get("password","")
        with db() as con:
            user = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = username
            audit(username, "LOGIN", "successful login")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    if session.get("username"): audit(session["username"], "LOGOUT", "signed out")
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    with db() as con:
        owned = con.execute("SELECT * FROM files WHERE owner_id=? ORDER BY id DESC", (user["id"],)).fetchall()
        shared = con.execute("""SELECT f.*, s.id AS share_id, s.active FROM shares s
            JOIN files f ON f.id=s.file_id WHERE s.recipient_id=? ORDER BY s.id DESC""", (user["id"],)).fetchall()
        users = con.execute("SELECT id,username FROM users WHERE id!=? ORDER BY username", (user["id"],)).fetchall()
        logs = con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 12").fetchall()
        all_shares = con.execute("""SELECT s.file_id,s.recipient_id,s.active,u.username FROM shares s
            JOIN users u ON u.id=s.recipient_id JOIN files f ON f.id=s.file_id
            WHERE f.owner_id=? ORDER BY s.id DESC""", (user["id"],)).fetchall()
    share_map = {}
    for sh in all_shares:
        share_map.setdefault(sh["file_id"], []).append(sh)
    return render_template("dashboard.html", user=user, owned=owned, shared=shared, users=users, logs=logs, share_map=share_map)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files.get("file")
    if not file or not file.filename:
        flash("Choose a file first."); return redirect(url_for("dashboard"))
    raw = file.read()
    if not raw: flash("Empty files are not accepted."); return redirect(url_for("dashboard"))
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(aes_key).encrypt(nonce, raw, None)
    user = current_user()
    pub = serialization.load_pem_public_key(user["public_key"].encode())
    wrapped = pub.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    stored = secrets.token_hex(20) + ".bin"
    with open(os.path.join(UPLOAD_DIR, stored), "wb") as f: f.write(encrypted)
    digest = hashlib.sha256(encrypted).hexdigest()
    with db() as con:
        con.execute("INSERT INTO files(owner_id,original_name,stored_name,wrapped_key,nonce,sha256,created_at) VALUES(?,?,?,?,?,?,?)",
                    (user["id"], file.filename, stored, b64(wrapped), b64(nonce), digest, now()))
    audit(user["username"], "UPLOAD_ENCRYPT", f"file={file.filename};sha256={digest}")
    flash("File encrypted and uploaded.")
    return redirect(url_for("dashboard"))

@app.route("/share/<int:file_id>", methods=["POST"])
@login_required
def share(file_id):
    recipient_id = request.form.get("recipient_id", type=int)
    owner = current_user()
    with db() as con:
        file = con.execute("SELECT * FROM files WHERE id=? AND owner_id=?", (file_id, owner["id"])).fetchone()
        recipient = con.execute("SELECT * FROM users WHERE id=?", (recipient_id,)).fetchone()
    if not file or not recipient or recipient_id == owner["id"]:
        flash("Invalid file or recipient."); return redirect(url_for("dashboard"))
    # Owner unwraps their AES key with their private key, then wraps it to recipient public key.
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        salt_text, token = owner["private_key_enc"].split(".", 1)
        salt = unb64(salt_text)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        key = base64.urlsafe_b64encode(kdf.derive(request.form.get("password","").encode()))
        private_pem = Fernet(key).decrypt(token.encode())
        private = serialization.load_pem_private_key(private_pem, password=None)
        aes_key = private.decrypt(unb64(file["wrapped_key"]), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        recipient_pub = serialization.load_pem_public_key(recipient["public_key"].encode())
        recipient_wrapped = recipient_pub.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        with db() as con:
            con.execute("INSERT INTO shares(file_id,recipient_id,wrapped_key,active,created_at) VALUES(?,?,?,1,?) ON CONFLICT(file_id,recipient_id) DO UPDATE SET wrapped_key=excluded.wrapped_key, active=1",
                        (file_id, recipient_id, b64(recipient_wrapped), now()))
        audit(owner["username"], "SHARE", f"file_id={file_id};recipient={recipient['username']}")
        flash(f"Shared with {recipient['username']}.")
    except Exception:
        flash("Could not share. Check your account password and try again.")
    return redirect(url_for("dashboard"))

@app.route("/revoke/<int:file_id>/<int:recipient_id>", methods=["POST"])
@login_required
def revoke(file_id, recipient_id):
    user = current_user()
    with db() as con:
        owned = con.execute("SELECT id FROM files WHERE id=? AND owner_id=?", (file_id,user["id"])).fetchone()
        if not owned: abort(403)
        con.execute("UPDATE shares SET active=0 WHERE file_id=? AND recipient_id=?", (file_id,recipient_id))
        rec = con.execute("SELECT username FROM users WHERE id=?", (recipient_id,)).fetchone()
    audit(user["username"], "REVOKE", f"file_id={file_id};recipient_id={recipient_id}")
    flash("Access revoked for future downloads.")
    return redirect(url_for("dashboard"))

@app.route("/download/<int:file_id>", methods=["POST"])
@login_required
def download(file_id):
    user = current_user()
    with db() as con:
        file = con.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
        share = con.execute("SELECT * FROM shares WHERE file_id=? AND recipient_id=? AND active=1", (file_id,user["id"])).fetchone()
        owner = con.execute("SELECT * FROM users WHERE id=?", (file["owner_id"],)).fetchone() if file else None
    if not file: abort(404)
    if file["owner_id"] == user["id"]:
        wrapped = file["wrapped_key"]
        private_user = user
    elif share:
        wrapped = share["wrapped_key"]
        private_user = user
    else:
        audit(user["username"], "DENIED", f"file_id={file_id}")
        abort(403)
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        salt_text, token = private_user["private_key_enc"].split(".",1)
        salt = unb64(salt_text)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        key = base64.urlsafe_b64encode(kdf.derive(request.form.get("password","").encode()))
        private_pem = Fernet(key).decrypt(token.encode())
        private = serialization.load_pem_private_key(private_pem,password=None)
        aes_key = private.decrypt(unb64(wrapped), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        path = os.path.join(UPLOAD_DIR,file["stored_name"])
        with open(path,"rb") as f: encrypted=f.read()
        if hashlib.sha256(encrypted).hexdigest() != file["sha256"]:
            audit(user["username"],"INTEGRITY_FAIL",f"file_id={file_id}")
            flash("Integrity check failed. The file may have been modified.")
            return redirect(url_for("dashboard"))
        plain = AESGCM(aes_key).decrypt(unb64(file["nonce"]), encrypted, None)
        audit(user["username"],"DOWNLOAD_DECRYPT",f"file_id={file_id}")
        return send_file(io.BytesIO(plain), as_attachment=True, download_name=file["original_name"])
    except Exception:
        flash("Decryption failed. Check your password or file integrity.")
        return redirect(url_for("dashboard"))

@app.route("/audit")
@login_required
def audit_page():
    with db() as con: logs = con.execute("SELECT * FROM audit ORDER BY id DESC").fetchall()
    # Verify chain from oldest to newest
    valid = True
    previous = "GENESIS"
    for row in reversed(logs):
        payload = f"{row['actor']}|{row['action']}|{row['detail']}|{row['timestamp']}|{previous}"
        if hashlib.sha256(payload.encode()).hexdigest() != row["entry_hash"] or row["prev_hash"] != previous:
            valid = False; break
        previous = row["entry_hash"]
    return render_template("audit.html", logs=logs, valid=valid)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
