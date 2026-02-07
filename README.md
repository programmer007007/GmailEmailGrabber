# Gmail Mail Grabber

A Flask-based web application that extracts and stores Gmail messages for specific date ranges. Users can authenticate with Gmail, fetch emails, and access them through a web interface or REST API.

## What This Does

This application allows you to:

- Connect your Gmail account via OAuth2
- Extract all emails from specific date ranges
- Store emails in a local SQLite database and JSONL files
- Access emails through a web dashboard or REST API
- Track extraction progress and batch history
- Support multiple users with individual API keys

## Features

- **Multi-User Support**: Multiple users can register and manage their own Gmail connections
- **Multi-Account Support**: Users can disconnect and reconnect different Gmail accounts
- **Full Email Content**: Fetches complete email bodies (both text and HTML), not just snippets
- **Smart HTML Cleaning**: Automatically strips unnecessary HTML tags, styles, and scripts to save space
- **Attachment Info**: Tracks attachment metadata (filename, type, size)
- **Complete Headers**: Captures From, To, CC, BCC, Subject, Date, and more
- **API Keys**: Each user gets a unique API key for secure API access
- **Progress Tracking**: Real-time progress updates showing email fetch status
- **Secure**: Password hashing, API key authentication, user data isolation

## Prerequisites

- Python 3.8 or higher
- Gmail account
- Google Cloud Project with Gmail API enabled

## Setup Instructions

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Get Google OAuth Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the **Gmail API**:
   - Navigate to "APIs & Services" > "Library"
   - Search for "Gmail API" and click "Enable"
4. Create OAuth 2.0 credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth client ID"
   - Choose "Web application"
   - Add authorized redirect URI: `http://localhost:5000/oauth2callback`
   - Download the credentials JSON file
5. Save the downloaded file as `credentials.json` in the project root directory

### 3. Configure Environment Variables

Create a `.env` file in the project root:

```bash
APP_SECRET=your-secret-key-here
ADMIN_USER=your-admin
ADMIN_PASS=your-admin-password
GOOGLE_CLIENT_SECRET_FILE=credentials.json
```

### 4. Run the Application

```bash
python app.py
```

The application will start on `http://localhost:5000`

### 5. First Time Setup

1. Open `http://localhost:5000` in your browser
2. Log in with the admin credentials from your `.env` file
3. Go to your profile page to get your API key
4. Click "Connect Gmail Account" to authenticate with Google
5. Grant the necessary permissions

## API Endpoints

All API requests require authentication via API key. Include the key in the `X-API-Key` header or as a `api_key` query parameter.

### 1. Request Email Extraction

**Endpoint**: `POST /api/request`

**Headers**:
```
Content-Type: application/json
X-API-Key: YOUR_API_KEY
```

**Body**:
```json
{
  "start_date": "2026-02-01",
  "end_date": "2026-02-07",
  "callback_url": "https://example.com/callback"
}
```

**Parameters**:
- `start_date` (optional): Start date in YYYY-MM-DD format. Defaults to today.
- `end_date` (optional): End date in YYYY-MM-DD format. Defaults to today.
- `callback_url` (optional): URL to receive completion notification.

**Response (New Request)**:
```json
{
  "status": "queued",
  "batch_id": 123,
  "start_date": "2026-02-01",
  "end_date": "2026-02-07",
  "callback_url": "https://example.com/callback"
}
```

**Response (Existing Batch)**:
```json
{
  "status": "completed",
  "batch_id": 123,
  "start_date": "2026-02-01",
  "end_date": "2026-02-07",
  "file_path": "/path/to/batch_123.jsonl",
  "total_messages": 42
}
```

**cURL Examples**:

```bash
# Request emails for a specific date range
curl -X POST "http://localhost:5000/api/request" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "start_date": "2026-02-01",
    "end_date": "2026-02-07",
    "callback_url": "https://example.com/callback"
  }'

# Request today's emails (no dates specified)
curl -X POST "http://localhost:5000/api/request" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{}'

# Request single date
curl -X POST "http://localhost:5000/api/request" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "start_date": "2026-02-07"
  }'
```

### 2. Check Batch Status

**Endpoint**: `GET /api/batch/<batch_id>`

**Headers**:
```
X-API-Key: YOUR_API_KEY
```

**Response**:
```json
{
  "id": 123,
  "user_id": 1,
  "gmail_account": "user@gmail.com",
  "start_date": "2026-02-01",
  "end_date": "2026-02-07",
  "status": "completed",
  "created_at": "2026-02-07T10:30:00",
  "completed_at": "2026-02-07T10:35:00",
  "file_path": "/path/to/batch_123.jsonl",
  "total_messages": 42,
  "processed_messages": 42,
  "estimated_total": 42,
  "callback_url": "https://example.com/callback",
  "error_message": null
}
```

**cURL Examples**:

```bash
# Using header authentication
curl -X GET "http://localhost:5000/api/batch/123" \
  -H "X-API-Key: YOUR_API_KEY"

# Using query parameter authentication
curl -X GET "http://localhost:5000/api/batch/123?api_key=YOUR_API_KEY"
```

### 3. Get Batch Messages

**Endpoint**: `GET /batch/<batch_id>/messages`

**Authentication**: Requires web login (session-based)

**Response**:
```json
{
  "batch_id": 123,
  "batch_info": {
    "id": 123,
    "start_date": "2026-02-01",
    "end_date": "2026-02-07",
    "status": "completed",
    "total_messages": 42
  },
  "messages": [
    {
      "id": 1,
      "message_id": "abc123",
      "subject": "Email Subject",
      "sender": "sender@example.com",
      "recipient": "you@gmail.com",
      "snippet": "Email preview...",
      "body_text": "Full text body",
      "body_html": "Cleaned HTML content",
      "attachments": [
        {
          "filename": "document.pdf",
          "mimeType": "application/pdf",
          "size": 12345
        }
      ],
      "formatted_date": "2026-02-07 10:30:00"
    }
  ]
}
```

**cURL Example**:
```bash
# First login to get session cookie
curl -c cookies.txt -X POST "http://localhost:5000/login" \
  -d "username=admin&password=yourpassword"

# Then use the cookie to access messages
curl -b cookies.txt "http://localhost:5000/batch/123/messages"
```

## Batch Status Values

- `queued` - Batch is waiting to start
- `running` - Batch is currently fetching emails
- `completed` - Batch finished successfully
- `error` - Batch failed (check error_message field)
- `auth_required` - Gmail authentication needed

## Email Data Format

Emails are stored in two formats:

1. **SQLite Database** (`app.db`): Structured storage for queries and web interface
2. **JSONL Files** (`data/batch_<id>.jsonl`): One JSON object per line for easy processing

### JSONL Record Format

```json
{
  "id": "message_id_from_gmail",
  "threadId": "thread_id",
  "internalDate": "1612345678000",
  "subject": "Email Subject",
  "from": "sender@example.com",
  "to": "recipient@gmail.com",
  "cc": "cc@example.com",
  "bcc": "bcc@example.com",
  "date": "Mon, 01 Feb 2026 10:30:00 +0000",
  "snippet": "Email preview snippet...",
  "body_text": "Plain text body content",
  "body_html": "Cleaned HTML content (text-focused)",
  "attachments": [
    {
      "filename": "document.pdf",
      "mimeType": "application/pdf",
      "size": 12345
    }
  ],
  "labels": ["INBOX", "UNREAD"]
}
```

### HTML Cleaning Process

To save storage space, HTML content is automatically cleaned:
- Removes: `<script>`, `<style>`, `<meta>`, `<link>`, inline styles
- Strips: Most HTML attributes (except `href` for links, `src` for images)
- Extracts: Clean text content with basic formatting preserved
- Keeps: Headings, paragraphs, links (with URLs), lists, emphasis
- Result: 60-90% size reduction while maintaining readability

## Security Notes

- Keep your `credentials.json` file secure (already in `.gitignore`)
- Never commit your `.env` file or API keys
- The `tokens/` directory contains OAuth tokens (already in `.gitignore`)
- Use strong passwords for user accounts
- Each user can only access their own batches
- API keys are unique per user and can be regenerated

## Project Structure

```
gmailMailGrabber/
├── app.py                 # Main Flask application
├── app.db                 # SQLite database
├── credentials.json       # Google OAuth credentials (DO NOT COMMIT)
├── .env                   # Environment variables (DO NOT COMMIT)
├── requirements.txt       # Python dependencies
├── api_examples.sh        # cURL examples script
├── data/                  # JSONL export files
├── tokens/                # OAuth tokens per user
└── templates/             # HTML templates
```

## Troubleshooting

### "Gmail authentication required" error
- Make sure you've connected your Gmail account through the web interface
- Try disconnecting and reconnecting your Gmail account

### "Invalid API key" error
- Verify your API key from the profile page
- Make sure you're including the key in the `X-API-Key` header

### OAuth redirect errors
- Ensure `http://localhost:5000/oauth2callback` is in your Google Cloud authorized redirect URIs
- Check that your `credentials.json` file is valid

### Rate limiting
- The app includes built-in delays to avoid hitting Gmail API rate limits
- If you encounter rate limit errors, wait a few minutes before retrying

## License

This project is provided as-is for personal use.
