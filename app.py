from werkzeug.middleware.proxy_fix import ProxyFix
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from functools import wraps

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from flask import Flask, abort, redirect, render_template, request, session, url_for, jsonify
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    raise ValueError("APP_SECRET environment variable is required. Please set it in your .env file.")

ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASS = os.getenv("ADMIN_PASS")

if not ADMIN_USER or not ADMIN_PASS:
    raise ValueError("ADMIN_USER and ADMIN_PASS environment variables are required. Please set them in your .env file.")

GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET_FILE", "credentials.json")
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
TOKENS_DIR = BASE_DIR / "tokens"
DB_PATH = DATA_DIR / "app.db"

DATA_DIR.mkdir(parents=True, exist_ok=True)
TOKENS_DIR.mkdir(parents=True, exist_ok=True)
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
BASE_URL = os.getenv("BASE_URL", "http://localhost:5000")


app = Flask(__name__)
app.secret_key = APP_SECRET

# Add ProxyFix to make Flask aware of proxy headers
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
    x_prefix=1
)

# Reduce OAuthlib warning for local dev when using http://localhost
os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    cur = conn.cursor()

    # Users table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            api_key TEXT UNIQUE NOT NULL,
            is_admin INTEGER DEFAULT 0,
            gmail_connected INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )

    # Email batches table (now linked to users)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS email_batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            gmail_account TEXT,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            file_path TEXT,
            total_messages INTEGER DEFAULT 0,
            callback_url TEXT,
            processed_messages INTEGER DEFAULT 0,
            estimated_total INTEGER DEFAULT 0,
            error_message TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id INTEGER NOT NULL,
            message_id TEXT NOT NULL,
            internal_date TEXT,
            subject TEXT,
            sender TEXT,
            recipient TEXT,
            snippet TEXT,
            body_text TEXT,
            body_html TEXT,
            attachments TEXT,
            filename TEXT,
            FOREIGN KEY(batch_id) REFERENCES email_batches(id)
        )
        """
    )

    # Create admin user if it doesn't exist
    cur.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USER,))
    if not cur.fetchone():
        api_key = secrets.token_urlsafe(32)
        cur.execute(
            """
            INSERT INTO users (username, password_hash, api_key, is_admin, created_at)
            VALUES (?, ?, ?, 1, ?)
            """,
            (ADMIN_USER, generate_password_hash(ADMIN_PASS), api_key, datetime.now(timezone.utc).isoformat())
        )

    conn.commit()
    conn.close()


def login_required(fn):
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


def get_current_user():
    """Get the current logged-in user from the database"""
    user_id = session.get("user_id")
    if not user_id:
        return None
    conn = db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user


def api_key_required(fn):
    """Decorator to require API key authentication for API endpoints"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if not api_key:
            return jsonify({"error": "API key required"}), 401

        conn = db()
        user = conn.execute("SELECT * FROM users WHERE api_key = ?", (api_key,)).fetchone()
        conn.close()

        if not user:
            return jsonify({"error": "Invalid API key"}), 401

        # Store user info in request context
        request.user = user
        return fn(*args, **kwargs)
    return wrapper


def load_credentials(user_id):
    """Load credentials for a specific user"""
    token_path = TOKENS_DIR / f"token_{user_id}.json"
    creds = None
    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(GoogleRequest())
        token_path.write_text(creds.to_json())
    return creds


def get_flow():
    # Use hardcoded production URL in production, auto-detect in dev
    if ENVIRONMENT == "production":
        redirect_uri = f"{BASE_URL}/oauth2callback"
    else:
        redirect_uri = url_for("oauth2callback", _external=True)
    
    return Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRET,
        scopes=SCOPES,
        redirect_uri=redirect_uri,
    )


def gmail_service(user_id):
    """Get Gmail service for a specific user"""
    creds = load_credentials(user_id)
    if not creds:
        return None
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def get_gmail_email(user_id):
    """Get the Gmail email address for a user"""
    try:
        service = gmail_service(user_id)
        if not service:
            return None
        profile = service.users().getProfile(userId="me").execute()
        return profile.get("emailAddress")
    except Exception as e:
        print(f"Error getting Gmail email: {e}")
        return None


def normalize_dates(start_date, end_date):
    if not start_date and not end_date:
        # Use local system time
        today = datetime.now().date()
        return today.isoformat(), today.isoformat()
    if not start_date:
        start_date = end_date
    if not end_date:
        end_date = start_date
    return start_date, end_date


def gmail_query(start_date, end_date):
    # Gmail query uses dates as YYYY/MM/DD and end is exclusive with before.
    # Gmail interprets dates in the user's Gmail account timezone
    # Parse as date only (not datetime) to let Gmail use its own timezone
    start = datetime.fromisoformat(start_date)
    # For end date, we want to include the entire day, so add 1 day
    end = datetime.fromisoformat(end_date) + timedelta(days=1)

    # Gmail search uses dates in YYYY/MM/DD format and interprets them in the account's timezone
    return f"after:{start.strftime('%Y/%m/%d')} before:{end.strftime('%Y/%m/%d')}"


def parse_email_body(payload):
    """Extract email body from Gmail API payload"""
    body_text = ""
    body_html = ""
    attachments = []

    def decode_data(data):
        """Decode base64url encoded data"""
        if data:
            import base64
            return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
        return ""

    def parse_parts(parts):
        """Recursively parse email parts"""
        nonlocal body_text, body_html, attachments

        for part in parts:
            mime_type = part.get("mimeType", "")
            filename = part.get("filename", "")

            # Handle attachments
            if filename:
                attachments.append({
                    "filename": filename,
                    "mimeType": mime_type,
                    "size": part.get("body", {}).get("size", 0)
                })

            # Handle body content
            if mime_type == "text/plain" and not body_text:
                body_data = part.get("body", {}).get("data")
                if body_data:
                    body_text = decode_data(body_data)

            elif mime_type == "text/html" and not body_html:
                body_data = part.get("body", {}).get("data")
                if body_data:
                    body_html = decode_data(body_data)

            # Recursively parse multipart
            if "parts" in part:
                parse_parts(part["parts"])

    # Check if message has parts (multipart)
    if "parts" in payload:
        parse_parts(payload["parts"])
    else:
        # Single part message
        mime_type = payload.get("mimeType", "")
        body_data = payload.get("body", {}).get("data")

        if body_data:
            decoded = decode_data(body_data)
            if mime_type == "text/plain":
                body_text = decoded
            elif mime_type == "text/html":
                body_html = decoded

    return {
        "text": body_text,
        "html": body_html,
        "attachments": attachments
    }


def clean_html_content(html_content):
    """
    Clean and minimize HTML content by:
    - Removing scripts, styles, and unnecessary tags
    - Stripping inline styles and most attributes
    - Keeping only essential structure (headings, paragraphs, links, lists)
    - Extracting readable text content
    """
    if not html_content or not html_content.strip():
        return ""

    try:
        soup = BeautifulSoup(html_content, 'html.parser')

        # Remove unwanted tags completely
        for tag in soup(['script', 'style', 'meta', 'link', 'noscript', 'iframe', 'embed', 'object']):
            tag.decompose()

        # Remove comments
        for comment in soup.findAll(text=lambda text: isinstance(text, str) and text.strip().startswith('<!--')):
            comment.extract()

        # Remove all attributes except href for links and src for images
        for tag in soup.find_all(True):
            # Keep only essential attributes
            if tag.name == 'a' and tag.has_attr('href'):
                attrs = {'href': tag['href']}
                tag.attrs = attrs
            elif tag.name == 'img' and tag.has_attr('src'):
                attrs = {'src': tag['src']}
                if tag.has_attr('alt'):
                    attrs['alt'] = tag['alt']
                tag.attrs = attrs
            else:
                tag.attrs = {}

        # Get cleaned HTML
        cleaned = str(soup)

        # Remove excessive whitespace
        cleaned = re.sub(r'\n\s*\n', '\n\n', cleaned)
        cleaned = re.sub(r' +', ' ', cleaned)

        # Further minimize: extract just text with basic structure
        # Option 1: Keep minimal HTML structure (recommended for readability)
        text_parts = []
        for element in soup.find_all(['p', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li', 'a', 'span', 'strong', 'em', 'br']):
            text = element.get_text(strip=True)
            if text:
                if element.name in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']:
                    text_parts.append(f"\n## {text}\n")
                elif element.name == 'a' and element.has_attr('href'):
                    text_parts.append(f"{text} ({element['href']})")
                elif element.name in ['p', 'div']:
                    text_parts.append(f"{text}\n")
                elif element.name == 'li':
                    text_parts.append(f"• {text}")
                else:
                    text_parts.append(text)

        if text_parts:
            result = ' '.join(text_parts)
            # Clean up extra spaces and newlines
            result = re.sub(r'\n{3,}', '\n\n', result)
            result = re.sub(r' +', ' ', result)
            return result.strip()

        # Fallback: just get all text
        return soup.get_text(separator=' ', strip=True)

    except Exception as e:
        print(f"Error cleaning HTML: {e}")
        # If cleaning fails, return plain text extraction
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            return soup.get_text(separator=' ', strip=True)
        except:
            return html_content


def insert_batch(conn, user_id, start_date, end_date, status, callback_url=None, gmail_account=None):
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO email_batches (user_id, gmail_account, start_date, end_date, status, created_at, callback_url)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            gmail_account,
            start_date,
            end_date,
            status,
            datetime.now(timezone.utc).isoformat(),
            callback_url,
        ),
    )
    conn.commit()
    return cur.lastrowid


def find_completed_batch(conn, user_id, start_date, end_date, gmail_account=None):
    """Find a completed batch for the same user, date range, and Gmail account"""
    cur = conn.cursor()

    if gmail_account:
        # Check for existing batch with the same Gmail account
        cur.execute(
            """
            SELECT * FROM email_batches
            WHERE user_id = ? AND start_date = ? AND end_date = ?
            AND status = 'completed' AND gmail_account = ?
            ORDER BY id DESC LIMIT 1
            """,
            (user_id, start_date, end_date, gmail_account),
        )
    else:
        # Fallback to old behavior if gmail_account not provided
        cur.execute(
            """
            SELECT * FROM email_batches
            WHERE user_id = ? AND start_date = ? AND end_date = ? AND status = 'completed'
            ORDER BY id DESC LIMIT 1
            """,
            (user_id, start_date, end_date),
        )

    return cur.fetchone()


def update_batch(conn, batch_id, **fields):
    keys = list(fields.keys())
    values = [fields[k] for k in keys]
    set_clause = ", ".join([f"{k} = ?" for k in keys])
    cur = conn.cursor()
    cur.execute(
        f"UPDATE email_batches SET {set_clause} WHERE id = ?",
        values + [batch_id],
    )
    conn.commit()


def extract_batch(batch_id, user_id, start_date, end_date):
    conn = db()
    try:
        service = gmail_service(user_id)
        if not service:
            update_batch(conn, batch_id, status="auth_required", error_message="Gmail authentication required")
            return

        q = gmail_query(start_date, end_date)
        batch_file = DATA_DIR / f"batch_{batch_id}.jsonl"
        total = 0
        page_token = None

        # First, get an estimate of total messages
        try:
            initial_response = (
                service.users()
                .messages()
                .list(userId="me", q=q, maxResults=1)
                .execute()
            )
            estimated_total = initial_response.get("resultSizeEstimate", 0)
            update_batch(conn, batch_id, status="running", file_path=str(batch_file), estimated_total=estimated_total, processed_messages=0)
        except Exception as e:
            update_batch(conn, batch_id, status="error", error_message=f"Failed to get message count: {str(e)}")
            return

        with batch_file.open("w", encoding="utf-8") as f:
            while True:
                response = (
                    service.users()
                    .messages()
                    .list(userId="me", q=q, pageToken=page_token, maxResults=100)
                    .execute()
                )
                messages = response.get("messages", [])

                for msg in messages:
                    msg_id = msg.get("id")
                    try:
                        # Fetch full message with body content
                        full_msg = (
                            service.users()
                            .messages()
                            .get(
                                userId="me",
                                id=msg_id,
                                format="full"
                            )
                            .execute()
                        )

                        # Parse headers
                        headers = {h["name"].lower(): h.get("value", "") for h in full_msg.get("payload", {}).get("headers", [])}

                        # Parse email body
                        body_data = parse_email_body(full_msg.get("payload", {}))

                        # Clean HTML to save space - extract just the content
                        cleaned_html = clean_html_content(body_data["html"]) if body_data["html"] else ""

                        # Build record with full content
                        record = {
                            "id": msg_id,
                            "threadId": full_msg.get("threadId"),
                            "internalDate": full_msg.get("internalDate"),
                            "subject": headers.get("subject", ""),
                            "from": headers.get("from", ""),
                            "to": headers.get("to", ""),
                            "cc": headers.get("cc", ""),
                            "bcc": headers.get("bcc", ""),
                            "date": headers.get("date", ""),
                            "snippet": full_msg.get("snippet", ""),
                            "body_text": body_data["text"],
                            "body_html": cleaned_html,  # Store cleaned HTML (much smaller)
                            "attachments": body_data["attachments"],
                            "labels": full_msg.get("labelIds", []),
                        }

                        # Write to JSONL file
                        f.write(json.dumps(record, ensure_ascii=True) + "\n")
                        total += 1

                        # Store in database
                        conn.execute(
                            """
                            INSERT INTO emails (batch_id, message_id, internal_date, subject, sender, recipient, snippet, body_text, body_html, attachments, filename)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                batch_id,
                                msg_id,
                                record.get("internalDate"),
                                record.get("subject"),
                                record.get("from"),
                                record.get("to"),
                                record.get("snippet"),
                                record.get("body_text"),
                                record.get("body_html"),
                                json.dumps(record.get("attachments", [])),
                                str(batch_file),
                            ),
                        )

                        # Update progress every 10 messages
                        if total % 10 == 0:
                            update_batch(conn, batch_id, processed_messages=total)

                        # Small sleep to avoid hammering the API.
                        time.sleep(0.05)
                    except Exception as e:
                        # Log error but continue processing
                        print(f"Error processing message {msg_id}: {e}")
                        continue

                conn.commit()

                page_token = response.get("nextPageToken")
                if not page_token:
                    break

                # Throttle between pages.
                time.sleep(0.2)

        update_batch(
            conn,
            batch_id,
            status="completed",
            total_messages=total,
            processed_messages=total,
            completed_at=datetime.now(timezone.utc).isoformat(),
        )

        # If a callback URL was provided, notify it with minimal payload.
        cur = conn.cursor()
        cur.execute("SELECT callback_url FROM email_batches WHERE id = ?", (batch_id,))
        row = cur.fetchone()
        callback_url = row["callback_url"] if row else None
        if callback_url:
            payload = {
                "batch_id": batch_id,
                "start_date": start_date,
                "end_date": end_date,
                "status": "completed",
                "file_path": str(batch_file),
                "total_messages": total,
            }
            try:
                requests.post(callback_url, json=payload, timeout=10)
            except Exception:
                pass
    except Exception as e:
        # Handle any unexpected errors
        error_msg = f"Extraction failed: {str(e)}"
        update_batch(conn, batch_id, status="error", error_message=error_msg)
        print(error_msg)
    finally:
        conn.close()


def start_extraction(user_id, start_date, end_date, callback_url=None, batch_id=None):
    # Get the Gmail account email for this user
    gmail_account = get_gmail_email(user_id)

    conn = db()
    if batch_id is None:
        # Create a new batch
        batch_id = insert_batch(conn, user_id, start_date, end_date, status="queued", callback_url=callback_url, gmail_account=gmail_account)
    conn.close()

    thread = threading.Thread(target=extract_batch, args=(batch_id, user_id, start_date, end_date), daemon=True)
    thread.start()
    return batch_id


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = user["is_admin"]
            return redirect(url_for("index"))

        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/profile")
@login_required
def profile():
    user = get_current_user()
    return render_template("profile.html", user=user)


@app.route("/regenerate-api-key", methods=["POST"])
@login_required
def regenerate_api_key():
    user = get_current_user()
    new_api_key = secrets.token_urlsafe(32)

    conn = db()
    conn.execute("UPDATE users SET api_key = ? WHERE id = ?", (new_api_key, user["id"]))
    conn.commit()
    conn.close()

    return redirect(url_for("profile"))


@app.route("/disconnect-gmail", methods=["POST"])
@login_required
def disconnect_gmail():
    user = get_current_user()
    token_path = TOKENS_DIR / f"token_{user['id']}.json"

    # Delete the token file if it exists
    if token_path.exists():
        token_path.unlink()

    # Update database
    # Note: Old batches are automatically isolated by gmail_account field
    # When user reconnects with a different Gmail account, duplicate check
    # will use the new gmail_account value, allowing re-fetching same dates
    conn = db()
    conn.execute("UPDATE users SET gmail_connected = 0 WHERE id = ?", (user["id"],))
    conn.commit()
    conn.close()

    return redirect(url_for("profile"))


@app.route("/")
@login_required
def index():
    user = get_current_user()
    conn = db()
    batches = conn.execute(
        "SELECT * FROM email_batches WHERE user_id = ? ORDER BY created_at DESC LIMIT 20",
        (user["id"],)
    ).fetchall()
    stats = conn.execute(
        "SELECT COUNT(*) as total_batches, SUM(total_messages) as total_messages FROM email_batches WHERE user_id = ? AND status = 'completed'",
        (user["id"],)
    ).fetchone()
    conn.close()
    return render_template("index.html", batches=batches, stats=stats, user=user)


@app.route("/auth/google")
@login_required
def auth_google():
    user = get_current_user()
    session["oauth_user_id"] = user["id"]
    flow = get_flow()
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    session["oauth_state"] = state
    return redirect(auth_url)


@app.route("/oauth2callback")
@login_required
def oauth2callback():
    user_id = session.get("oauth_user_id")
    if not user_id:
        return redirect(url_for("index"))

    flow = get_flow()
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials

    token_path = TOKENS_DIR / f"token_{user_id}.json"
    token_path.write_text(creds.to_json())

    # Update user's gmail_connected status
    conn = db()
    conn.execute("UPDATE users SET gmail_connected = 1 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("index"))


@app.route("/fetch", methods=["POST"])
@login_required
def fetch_emails():
    user = get_current_user()
    start_date, end_date = normalize_dates(
        request.form.get("start_date"),
        request.form.get("end_date"),
    )

    # Get current Gmail account for duplicate check
    gmail_account = get_gmail_email(user["id"])

    conn = db()
    existing = find_completed_batch(conn, user["id"], start_date, end_date, gmail_account)
    conn.close()
    if existing:
        return redirect(url_for("index"))

    start_extraction(user["id"], start_date, end_date)
    return redirect(url_for("index"))


@app.route("/batch/<int:batch_id>/refetch", methods=["POST"])
@login_required
def refetch_batch(batch_id):
    user = get_current_user()

    # Get the batch details
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM email_batches WHERE id = ? AND user_id = ?",
        (batch_id, user["id"])
    )
    batch = cur.fetchone()

    if not batch:
        conn.close()
        abort(404)

    # Check if batch is already running or queued
    if batch["status"] in ["running", "queued"]:
        conn.close()
        return redirect(url_for("index"))

    # Delete old emails associated with this batch
    cur.execute("DELETE FROM emails WHERE batch_id = ?", (batch_id,))

    # Reset the batch status to queued
    cur.execute(
        """
        UPDATE email_batches
        SET status = 'queued',
            total_messages = 0,
            processed_messages = 0,
            estimated_total = 0,
            error_message = NULL,
            completed_at = NULL
        WHERE id = ?
        """,
        (batch_id,)
    )
    conn.commit()
    conn.close()

    # Start the extraction using the existing batch's date range
    start_extraction(user["id"], batch["start_date"], batch["end_date"], batch_id=batch_id)

    return redirect(url_for("index"))


@app.route("/api/request", methods=["POST"])
@api_key_required
def api_request():
    user = request.user
    data = request.get_json(silent=True) or {}
    start_date, end_date = normalize_dates(data.get("start_date"), data.get("end_date"))
    callback_url = data.get("callback_url")

    # Get current Gmail account for duplicate check
    gmail_account = get_gmail_email(user["id"])

    conn = db()
    existing = find_completed_batch(conn, user["id"], start_date, end_date, gmail_account)

    if existing:
        # Fetch the actual email messages from the database
        messages = conn.execute(
            """
            SELECT message_id, internal_date, subject, sender, recipient,
                   snippet, body_text, body_html, attachments
            FROM emails
            WHERE batch_id = ?
            ORDER BY internal_date DESC
            """,
            (existing["id"],)
        ).fetchall()

        # Convert messages to list of dicts
        messages_list = []
        for msg in messages:
            msg_dict = dict(msg)
            if msg_dict.get('attachments'):
                try:
                    msg_dict['attachments'] = json.loads(msg_dict['attachments'])
                except:
                    msg_dict['attachments'] = []
            else:
                msg_dict['attachments'] = []
            messages_list.append(msg_dict)

        conn.close()
        return jsonify(
            {
                "status": "completed",
                "batch_id": existing["id"],
                "start_date": existing["start_date"],
                "end_date": existing["end_date"],
                "total_messages": existing["total_messages"],
                "messages": messages_list
            }
        )

    conn.close()
    batch_id = start_extraction(user["id"], start_date, end_date, callback_url=callback_url)
    return jsonify(
        {
            "status": "queued",
            "batch_id": batch_id,
            "start_date": start_date,
            "end_date": end_date,
            "callback_url": callback_url,
        }
    )


@app.route("/api/batch/<int:batch_id>")
@api_key_required
def api_batch_status(batch_id):
    user = request.user
    conn = db()
    row = conn.execute(
        "SELECT * FROM email_batches WHERE id = ? AND user_id = ?",
        (batch_id, user["id"])
    ).fetchone()

    if not row:
        conn.close()
        abort(404)

    # Fetch messages for this batch
    messages = conn.execute(
        """
        SELECT message_id, internal_date, subject, sender, recipient,
               snippet, body_text, body_html, attachments
        FROM emails
        WHERE batch_id = ?
        ORDER BY internal_date DESC
        """,
        (batch_id,)
    ).fetchall()

    conn.close()

    # Convert messages to list of dicts
    messages_list = []
    for msg in messages:
        msg_dict = dict(msg)
        if msg_dict.get('attachments'):
            try:
                msg_dict['attachments'] = json.loads(msg_dict['attachments'])
            except:
                msg_dict['attachments'] = []
        else:
            msg_dict['attachments'] = []
        messages_list.append(msg_dict)

    batch_info = dict(row)
    batch_info['messages'] = messages_list

    return jsonify(batch_info)


@app.route("/batch/<int:batch_id>/messages")
@login_required
def batch_messages(batch_id):
    """Get all messages for a batch"""
    user = get_current_user()
    conn = db()

    # Verify the batch belongs to the user
    batch = conn.execute(
        "SELECT * FROM email_batches WHERE id = ? AND user_id = ?",
        (batch_id, user["id"])
    ).fetchone()

    if not batch:
        conn.close()
        abort(404)

    # Fetch all messages for this batch
    messages = conn.execute(
        """
        SELECT id, message_id, internal_date, subject, sender, recipient,
               snippet, body_text, body_html, attachments
        FROM emails
        WHERE batch_id = ?
        ORDER BY internal_date DESC
        """,
        (batch_id,)
    ).fetchall()

    conn.close()

    # Convert to list of dicts and parse attachments
    messages_list = []
    for msg in messages:
        msg_dict = dict(msg)
        if msg_dict.get('attachments'):
            try:
                msg_dict['attachments'] = json.loads(msg_dict['attachments'])
            except:
                msg_dict['attachments'] = []
        else:
            msg_dict['attachments'] = []

        # Format the date for display
        if msg_dict.get('internal_date'):
            try:
                timestamp = int(msg_dict['internal_date']) / 1000
                dt = datetime.fromtimestamp(timestamp)
                msg_dict['formatted_date'] = dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                msg_dict['formatted_date'] = 'N/A'
        else:
            msg_dict['formatted_date'] = 'N/A'

        messages_list.append(msg_dict)

    return jsonify({
        'batch_id': batch_id,
        'batch_info': dict(batch),
        'messages': messages_list
    })


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
