from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import uuid
import json
import logging
from datetime import datetime, timedelta
from functools import wraps
import threading
import time

# Optional imports with fallbacks
try:
    from flask_cors import CORS
    CORS_AVAILABLE = True
except ImportError:
    CORS_AVAILABLE = False

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False

try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

try:
    from PIL import Image
    import io
    import base64
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# Optional MongoDB
USE_MONGO = False
try:
	from pymongo import MongoClient, ASCENDING
	MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017')
	_mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
	_mongo_client.admin.command('ping')
	db = _mongo_client['fixzen']
	USE_MONGO = True
except Exception:
	USE_MONGO = False

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-in-production'

# Configure optional features
if JWT_AVAILABLE:
    app.config['JWT_SECRET_KEY'] = 'jwt-secret-string-change-in-production'
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Enable CORS for API endpoints if available
if CORS_AVAILABLE:
    CORS(app, resources={r"/api/*": {"origins": "*"}})

# Rate limiting if available
if LIMITER_AVAILABLE:
	limiter = Limiter(
		key_func=get_remote_address,
		default_limits=["200 per day", "50 per hour"]
	)
	limiter.init_app(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    handlers=[
        logging.FileHandler('fixzen.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Uploads config
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

def allowed_file(filename: str) -> bool:
	return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------------- Enhanced DB Setup ----------------
def init_db():
	if USE_MONGO:
		# Create indexes and seed demo data
		db.users.create_index([('email', ASCENDING)], unique=True)
		if db.healings.count_documents({}) == 0:
			db.healings.insert_many([
				{"date": "2025-08-15", "location": "Sector 12", "water_used": 12.5},
				{"date": "2025-08-16", "location": "Main Street", "water_used": 9.8},
				{"date": "2025-08-17", "location": "Park Ave", "water_used": 14.2},
			])
		# Remove demo reports - only show user-submitted reports
		return

	# SQLite fallback with enhanced schema
	conn = sqlite3.connect("users.db")
	cursor = conn.cursor()
	
	# Enhanced users table
	cursor.execute("""
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			role TEXT DEFAULT 'user',
			created_at TEXT DEFAULT CURRENT_TIMESTAMP,
			last_login TEXT,
			is_active BOOLEAN DEFAULT 1,
			profile_image TEXT,
			phone TEXT,
			address TEXT
		)
	""")
	
	# API tokens table for JWT management
	cursor.execute("""
		CREATE TABLE IF NOT EXISTS api_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			token_hash TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			created_at TEXT DEFAULT CURRENT_TIMESTAMP,
			is_revoked BOOLEAN DEFAULT 0,
			FOREIGN KEY (user_id) REFERENCES users (id)
		)
	""")
	
	# Notifications table
	cursor.execute("""
		CREATE TABLE IF NOT EXISTS notifications (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			title TEXT NOT NULL,
			message TEXT NOT NULL,
			type TEXT DEFAULT 'info',
			is_read BOOLEAN DEFAULT 0,
			created_at TEXT DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users (id)
		)
	""")

	# Healing data table for Liquid Healing page
	cursor.execute("""
		CREATE TABLE IF NOT EXISTS healings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			date TEXT NOT NULL,
			location TEXT NOT NULL,
			water_used REAL NOT NULL
		)
	""")

	# Crack reports table
	cursor.execute("""
		CREATE TABLE IF NOT EXISTS cracks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			crack_id TEXT,
			image_path TEXT,
			lat TEXT,
			lng TEXT,
			length_mm REAL,
			width_mm REAL,
			created_at TEXT NOT NULL
		)
	""")

	# Road quality reports table
	cursor.execute("""
		CREATE TABLE IF NOT EXISTS reports (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location TEXT NOT NULL,
			is_street BOOLEAN NOT NULL,
			road_quality TEXT NOT NULL,
			created_at TEXT NOT NULL,
			user_id INTEGER,
			FOREIGN KEY (user_id) REFERENCES users (id)
		)
	""")

	# Clear any existing demo data and start fresh
	cursor.execute("DELETE FROM reports WHERE user_id IS NULL")
	
	# Optional seed data for demo if table empty
	cursor.execute("SELECT COUNT(*) FROM healings")
	count = cursor.fetchone()[0]
	if count == 0:
		cursor.executemany(
			"INSERT INTO healings (date, location, water_used) VALUES (?, ?, ?)",
			[
				("2025-08-15", "Sector 12", 12.5),
				("2025-08-16", "Main Street", 9.8),
				("2025-08-17", "Park Ave", 14.2),
			],
		)

	conn.commit()
	conn.close()

init_db()


# ---------------- Pages ----------------
# ---------------- Home Page ----------------
@app.route("/")
def home():
	if "user" not in session:
		return render_template("code1.html")
	
	# Fetch reports for display - only current user's reports
	current_user_id = session.get('user_id')
	reports = []
	
	if current_user_id:
		try:
			if USE_MONGO:
				reports = list(db.reports.find({"user_id": current_user_id}).sort("created_at", -1).limit(5))
			else:
				conn = sqlite3.connect("users.db")
				cursor = conn.cursor()
				cursor.execute("""
					SELECT id, location, is_street, road_quality, created_at 
					FROM reports 
					WHERE user_id = ? 
					ORDER BY created_at DESC 
					LIMIT 5
				""", (current_user_id,))
				
				for r in cursor.fetchall():
					reports.append({
						"id": r[0],
						"location": r[1], 
						"is_street": r[2], 
						"road_quality": r[3], 
						"created_at": r[4]
					})
				conn.close()
				
			logger.info(f"Home page: Retrieved {len(reports)} reports for user {current_user_id}")
			
		except Exception as e:
			logger.error(f"Error retrieving reports for home page: {str(e)}")
			reports = []
	
	return render_template("code1.html", reports=reports)


@app.route("/submit_report", methods=["POST"])
def submit_report():
	location = request.form.get("location")
	is_street = request.form.get("street") == "Yes"
	road_quality = request.form.get("quality")
	
	if not location or not road_quality:
		flash("Please fill in all required fields.", "error")
		return redirect(url_for("home"))
	
	# Save report to database with current user ID
	current_user_id = session.get('user_id')
	
	# Force user_id to 1 if not set (temporary fix)
	if not current_user_id:
		current_user_id = "1"
		session["user_id"] = "1"
	
	try:
		conn = sqlite3.connect("users.db")
		cursor = conn.cursor()
		
		# Insert the report
		cursor.execute(
			"INSERT INTO reports (location, is_street, road_quality, created_at, user_id) VALUES (?, ?, ?, ?, ?)",
			(location, is_street, road_quality, datetime.utcnow().isoformat(), current_user_id)
		)
		report_id = cursor.lastrowid
		conn.commit()
		conn.close()
		
		flash(f"Report submitted successfully! Location: {location}, Quality: {road_quality}", "success")
		
	except Exception as e:
		logger.error(f"Error saving report: {str(e)}")
		flash("Error saving report. Please try again.", "error")
	
	return redirect(url_for("home"))


@app.route("/signup", methods=["GET"])
def signup_page():
	return render_template("signup.html")


# ---------------- Signup API ----------------
@app.route("/signup", methods=["POST"])
def signup():
	name = request.form.get("name")
	email = request.form.get("email")
	password = request.form.get("password")

	if not name or not email or not password:
		return "All fields are required", 400

	try:
		if USE_MONGO:
			db.users.insert_one({"name": name, "email": email, "password": password})
			return redirect(url_for("login"))
		# SQLite
		conn = sqlite3.connect("users.db")
		cursor = conn.cursor()
		cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
					   (name, email, password))
		conn.commit()
		conn.close()
		return redirect(url_for("login"))  # redirect to login after signup
	except Exception:
		return "Email already exists", 409


# ---------------- Login API ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
	# If already logged in and trying to access login page, send to home
	if request.method == "GET" and session.get("user"):
		return redirect(url_for("home"))

	if request.method == "POST":
		email = request.form["email"]
		password = request.form["password"]

		if USE_MONGO:
			user = db.users.find_one({"email": email, "password": password})
		else:
			# Query the database for user authentication
			conn = sqlite3.connect("users.db")
			cursor = conn.cursor()
			cursor.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, password))
			user = cursor.fetchone()
			conn.close()

		if user:
			if USE_MONGO:
				name_value = user.get("name")
				user_id = str(user.get("_id"))
			else:
				name_value = user[1]
				user_id = str(user[0])  # Convert to string and store
			
			# Clear session first
			session.clear()
			
			# Set session data
			session["user"] = email
			session["user_id"] = user_id
			session["user_name"] = name_value
			
			logger.info(f"Login successful - User ID: {user_id}, Email: {email}")
			flash("Login successful!", "success")
			return redirect(url_for("home"))
		else:
			flash("Invalid email or password.", "error")

	return render_template("login.html")  # for GET request


# ---------------- Liquid Healing Page ----------------
@app.route("/healing", methods=["GET"])
def healing_page():
	if USE_MONGO:
		rows = list(db.healings.find({}, {"_id": 0, "date": 1, "location": 1, "water_used": 1}).sort("date", ASCENDING))
		records = rows
	else:
		conn = sqlite3.connect("users.db")
		cursor = conn.cursor()
		cursor.execute("SELECT date, location, water_used FROM healings ORDER BY date")
		rows = cursor.fetchall()
		conn.close()
		records = [
			{"date": r[0], "location": r[1], "water_used": r[2]}
			for r in rows
		]

	return render_template("healing.html", records=records)


# ---------------- Crack Detection Page ----------------
# (Removed duplicate route - enhanced version is below)


# ---------------- Reports Page ----------------
@app.route("/reports")
def reports_page():
    current_user_id = session.get('user_id')
    
    if not current_user_id:
        flash("Please log in to view your reports.", "error")
        return redirect(url_for("login"))
    
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, location, is_street, road_quality, created_at 
            FROM reports 
            WHERE user_id = ?
            ORDER BY created_at DESC
        """, (current_user_id,))
        
        reports = []
        for r in cursor.fetchall():
            reports.append({
                "id": r[0],
                "location": r[1], 
                "is_street": r[2], 
                "road_quality": r[3], 
                "created_at": r[4]
            })
        conn.close()
        
    except Exception as e:
        logger.error(f"Error retrieving reports: {str(e)}")
        reports = []
    
    return render_template("reports.html", reports=reports)

# ---------------- Analytics Page ----------------
@app.route("/analytics", methods=["GET", "OPTIONS"])
def analytics_page():
	if request.method == "OPTIONS":
		return "", 200
	if USE_MONGO:
		total_users = db.users.count_documents({})
		total_healings = db.healings.count_documents({})
		total_cracks = db.get_collection('cracks').count_documents({}) if 'cracks' in db.list_collection_names() else 0
		avg_doc = list(db.healings.aggregate([{ "$group": { "_id": None, "avg": { "$avg": "$water_used" } } }]))
		avg_water = round(avg_doc[0]['avg'], 2) if avg_doc else 0
		series = list(db.healings.aggregate([
			{ "$group": { "_id": "$date", "total": { "$sum": "$water_used" } } },
			{ "$sort": { "_id": 1 } }
		]))
		chart_labels = [s['_id'] for s in series]
		chart_values = [float(s['total']) for s in series]
	else:
		conn = sqlite3.connect("users.db")
		cursor = conn.cursor()
		cursor.execute("SELECT COUNT(*) FROM users")
		total_users = cursor.fetchone()[0]
		cursor.execute("SELECT COUNT(*) FROM healings")
		total_healings = cursor.fetchone()[0]
		cursor.execute("SELECT COUNT(*) FROM cracks")
		total_cracks = cursor.fetchone()[0]
		cursor.execute("SELECT COALESCE(AVG(water_used), 0) FROM healings")
		avg_water = round(cursor.fetchone()[0] or 0, 2)
		cursor.execute("SELECT date, SUM(water_used) FROM healings GROUP BY date ORDER BY date")
		rows = cursor.fetchall()
		conn.close()
		chart_labels = [r[0] for r in rows]
		chart_values = [float(r[1]) for r in rows]

	metrics = {
		"total_users": total_users,
		"total_healings": total_healings,
		"total_cracks": total_cracks,
		"avg_water": avg_water,
	}
	return render_template("analytics.html", metrics=metrics, chart_labels=chart_labels, chart_values=chart_values)


# ---------------- Optional Dashboard ----------------
@app.route("/dashboard")
def dashboard():
	if "user" not in session:
		return redirect(url_for("login"))
	return render_template("dashboard.html", user=session["user"])


# ---------------- Logout ----------------
@app.route("/logout")
def logout():
	session.clear()
	flash("You have been logged out.")
	return redirect(url_for("home"))

# Import and register API blueprint (optional)
try:
    from backend_api import api
    app.register_blueprint(api)
    logger.info("API blueprint registered successfully")
except ImportError as e:
    logger.warning(f"Could not import API blueprint: {e}")
except Exception as e:
    logger.error(f"Error registering API blueprint: {e}")

# Authentication helper functions
def generate_jwt_token(user_id, email):
    """Generate JWT token for user authentication"""
    if not JWT_AVAILABLE:
        return None
    return jwt.encode({
        'user_id': user_id,
        'email': email,
        'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
    }, app.config['JWT_SECRET_KEY'], algorithm='HS256')

def create_notification(user_id, title, message, notification_type='info'):
    """Create a new notification for user"""
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO notifications (user_id, title, message, type, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, title, message, notification_type, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        logger.info(f"Notification created for user {user_id}: {title}")
    except Exception as e:
        logger.error(f"Failed to create notification: {str(e)}")

# Background task for processing images
def process_crack_image(image_path, crack_id):
    """Background task to simulate AI processing of crack images"""
    try:
        time.sleep(2)  # Simulate processing time
        
        # Simulate AI analysis results
        import random
        confidence = round(random.uniform(85.0, 99.9), 1)
        severity = random.choice(['Low', 'Medium', 'High', 'Critical'])
        
        logger.info(f"Processed crack {crack_id} with {confidence}% confidence, severity: {severity}")
        
        # Update database with analysis results
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE cracks SET confidence = ?, severity = ?, processed = 1
            WHERE crack_id = ?
        """, (confidence, severity, crack_id))
        conn.commit()
        conn.close()
        
    except Exception as e:
        logger.error(f"Error processing crack image {crack_id}: {str(e)}")

# Enhanced crack submission with background processing
@app.route("/crack", methods=["GET", "POST"])
def crack_page():
    if request.method == "POST":
        crack_id = request.form.get("crack_id") or str(uuid.uuid4())
        latitude = request.form.get("latitude")
        longitude = request.form.get("longitude")
        length_mm = request.form.get("length_mm")
        width_mm = request.form.get("width_mm")

        image = request.files.get("image")
        image_filename = None
        if image and allowed_file(image.filename):
            stamped = datetime.now().strftime("%Y%m%d_%H%M%S_")
            filename = stamped + secure_filename(image.filename)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(save_path)
            image_filename = filename
            
            # Start background processing
            threading.Thread(
                target=process_crack_image, 
                args=(save_path, crack_id),
                daemon=True
            ).start()

        # Enhanced database insertion
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO cracks (crack_id, image_path, lat, lng, length_mm, width_mm, created_at, user_id, processed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            crack_id, image_filename, latitude, longitude,
            float(length_mm) if length_mm else None,
            float(width_mm) if width_mm else None,
            datetime.utcnow().isoformat(),
            session.get('user_id'),
            0  # Not processed yet
        ))
        conn.commit()
        conn.close()

        # Create notification
        if session.get('user_id'):
            create_notification(
                session['user_id'],
                "Crack Report Submitted",
                f"Your crack report {crack_id} is being processed by our AI system.",
                "success"
            )

        flash("Crack report submitted and is being processed by AI.", "success")
        return redirect(url_for("crack_page"))

    return render_template("crack.html")

if __name__ == "__main__":
    init_db()
    logger.info("Starting FixZen application with enhanced backend...")
    app.run(debug=True, host='0.0.0.0', port=5000)
