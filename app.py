import os
import sqlite3
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ----------------- CONFIG -----------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "engine_diag.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

app = Flask(__name__)
app.secret_key = "change_this_secret_key"   # change for production!
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# ----------------- DB HELPERS -----------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    # Users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
    """)

    # Cases table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            engine_type TEXT,
            symptoms TEXT NOT NULL,
            image_filename TEXT,
            diagnosis TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)

    conn.commit()
    conn.close()


# ----------------- UTILS -----------------
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(view_func):
    from functools import wraps

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


def suggest_solutions(engine_type: str, symptoms: str) -> str:
    """
    SIMPLE rule-based diagnostic engine.
    Later you can replace this with AI.
    """
    text = (symptoms or "").lower()
    engine = (engine_type or "").lower()

    suggestions = []

    # Smoke types
    if "black smoke" in text:
        suggestions.append(
            "- Possible over-fuelling or restricted air supply.\n"
            "  → Check air filter, turbocharger, fuel injectors, and boost leaks."
        )
    if "white smoke" in text:
        suggestions.append(
            "- Possible unburned fuel or low compression.\n"
            "  → Check injection timing, compression, and cold-start system."
        )
    if "blue smoke" in text or "oil smoke" in text:
        suggestions.append(
            "- Possible oil burning.\n"
            "  → Check turbocharger seals, valve stem seals, piston rings."
        )

    # Starting issues
    if "no start" in text or "won't start" in text or "wont start" in text:
        suggestions.append(
            "- Engine not starting.\n"
            "  → Check battery voltage, starter motor, fuel supply, emergency stops and safety shutdowns."
        )

    # Knocking / noise
    if "knock" in text or "knocking" in text or "metallic noise" in text:
        suggestions.append(
            "- Abnormal knocking noise.\n"
            "  → Check injection timing, bearing clearances, loose connecting rods, or detonation."
        )

    # Overheating
    if "overheat" in text or "overheating" in text or "high temperature" in text:
        suggestions.append(
            "- Engine overheating.\n"
            "  → Check cooling water flow, thermostat, sea strainer (for marine), coolant level, and pump impeller."
        )

    # Low power
    if "low power" in text or "no power" in text or "loss of power" in text:
        suggestions.append(
            "- Loss of power.\n"
            "  → Check fuel filters, air filters, turbocharger performance, and exhaust backpressure."
        )

    # Marine-specific
    if "marine" in engine or "ship" in engine:
        suggestions.append(
            "- Marine-specific checks.\n"
            "  → Inspect sea-water inlet, strainers, cooling jackets, and gearbox load."
        )

    if not suggestions:
        suggestions.append(
            "- No clear rule-based match found.\n"
            "  → Check basics: fuel, air, compression, and lubrication. Consider AI analysis later."
        )

    return "\n\n".join(suggestions)


# ----------------- ROUTES: AUTH -----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("register"))

        conn = get_db()
        cur = conn.cursor()

        # Check if user exists
        cur.execute("SELECT id FROM users WHERE username = ?;", (username,))
        existing = cur.fetchone()
        if existing:
            flash("Username already taken.", "danger")
            conn.close()
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?);",
            (username, password_hash),
        )
        conn.commit()
        conn.close()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE username = ?;", (username,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = username
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ----------------- ROUTES: MAIN PAGES -----------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session["user_id"]
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, engine_type, symptoms, image_filename, diagnosis, created_at "
        "FROM cases WHERE user_id = ? ORDER BY id DESC;",
        (user_id,),
    )
    cases = cur.fetchall()
    conn.close()
    return render_template("dashboard.html", cases=cases)


@app.route("/diagnose", methods=["GET", "POST"])
@login_required
def diagnose():
    if request.method == "POST":
        engine_type = request.form.get("engine_type", "").strip()
        symptoms = request.form.get("symptoms", "").strip()
        image_file = request.files.get("image")

        if not symptoms:
            flash("Please describe the symptoms.", "danger")
            return redirect(url_for("diagnose"))

        image_filename = None
        if image_file and image_file.filename:
            if allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename)
                name, ext = os.path.splitext(filename)
                filename = f"{name}_{int(datetime.now().timestamp())}{ext}"
                image_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                image_file.save(image_path)
                image_filename = filename
            else:
                flash("Invalid image format. Use png/jpg/jpeg/gif.", "danger")
                return redirect(url_for("diagnose"))

        diagnosis_text = suggest_solutions(engine_type, symptoms)
        created_at = datetime.utcnow().isoformat(timespec="seconds")

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO cases (user_id, engine_type, symptoms, image_filename, diagnosis, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?);",
            (session["user_id"], engine_type, symptoms, image_filename, diagnosis_text, created_at),
        )
        conn.commit()
        case_id = cur.lastrowid
        conn.close()

        return redirect(url_for("view_result", case_id=case_id))

    return render_template("diagnose.html")


@app.route("/result/<int:case_id>")
@login_required
def view_result(case_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, engine_type, symptoms, image_filename, diagnosis, created_at "
        "FROM cases WHERE id = ? AND user_id = ?;",
        (case_id, session["user_id"]),
    )
    case = cur.fetchone()
    conn.close()

    if not case:
        flash("Case not found.", "danger")
        return redirect(url_for("dashboard"))

    return render_template("result.html", case=case)


@app.route("/uploads/<filename>")
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ----------------- MAIN -----------------
if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
