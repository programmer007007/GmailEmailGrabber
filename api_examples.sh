#!/bin/bash
# Gmail Mail Grabber - API Usage Examples with curl
# Replace YOUR_API_KEY with your actual API key from the profile page

API_KEY="YOUR_API_KEY"
BASE_URL="http://localhost:5000"

echo "==================================="
echo "Gmail Mail Grabber API Examples"
echo "==================================="
echo ""

# Example 1: Request emails for a specific date range
echo "1. Request emails for a date range (with callback URL)"
echo "-----------------------------------"
curl -X POST "${BASE_URL}/api/request" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d '{
    "start_date": "2026-02-01",
    "end_date": "2026-02-07",
    "callback_url": "https://example.com/callback"
  }'
echo -e "\n"

# Example 2: Request emails for today (no dates specified)
echo "2. Request emails for today (no dates specified)"
echo "-----------------------------------"
curl -X POST "${BASE_URL}/api/request" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d '{}'
echo -e "\n"

# Example 3: Request emails without callback URL
echo "3. Request emails for a single date (no callback)"
echo "-----------------------------------"
curl -X POST "${BASE_URL}/api/request" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d '{
    "start_date": "2026-02-07",
    "end_date": "2026-02-07"
  }'
echo -e "\n"

# Example 4: Check batch status (replace 1 with your actual batch_id)
echo "4. Check batch status"
echo "-----------------------------------"
BATCH_ID=1
curl -X GET "${BASE_URL}/api/batch/${BATCH_ID}" \
  -H "X-API-Key: ${API_KEY}"
echo -e "\n"

# Example 5: Using API key as query parameter instead of header
echo "5. Alternative: API key as query parameter"
echo "-----------------------------------"
curl -X GET "${BASE_URL}/api/batch/${BATCH_ID}?api_key=${API_KEY}"
echo -e "\n"

echo "==================================="
echo "Response Formats"
echo "==================================="
echo ""
echo "POST /api/request - New Request Response:"
echo '{
  "status": "queued",
  "batch_id": 123,
  "start_date": "2026-02-01",
  "end_date": "2026-02-07",
  "callback_url": "https://example.com/callback"
}'
echo ""
echo "POST /api/request - Existing Completed Batch Response (with messages):"
echo '{
  "status": "completed",
  "batch_id": 123,
  "start_date": "2026-02-01",
  "end_date": "2026-02-07",
  "total_messages": 2,
  "messages": [
    {
      "message_id": "abc123",
      "internal_date": "1738934400000",
      "subject": "Meeting Tomorrow",
      "sender": "colleague@example.com",
      "recipient": "you@gmail.com",
      "snippet": "Hi, just confirming our meeting...",
      "body_text": "Full email text content here...",
      "body_html": "Cleaned HTML content...",
      "attachments": [
        {
          "filename": "document.pdf",
          "mimeType": "application/pdf",
          "size": 12345
        }
      ]
    }
  ]
}'
echo ""
echo "GET /api/batch/<batch_id> - Batch Status Response (with messages):"
echo '{
  "id": 123,
  "user_id": 1,
  "gmail_account": "user@gmail.com",
  "start_date": "2026-02-01",
  "end_date": "2026-02-07",
  "status": "completed",
  "created_at": "2026-02-07T10:30:00",
  "completed_at": "2026-02-07T10:35:00",
  "file_path": "/path/to/batch_123.jsonl",
  "total_messages": 2,
  "processed_messages": 2,
  "estimated_total": 2,
  "callback_url": "https://example.com/callback",
  "error_message": null,
  "messages": [
    {
      "message_id": "abc123",
      "internal_date": "1738934400000",
      "subject": "Meeting Tomorrow",
      "sender": "colleague@example.com",
      "recipient": "you@gmail.com",
      "snippet": "Hi, just confirming our meeting...",
      "body_text": "Full email text content here...",
      "body_html": "Cleaned HTML content...",
      "attachments": []
    }
  ]
}'
echo ""
echo "==================================="
echo "Status Values"
echo "==================================="
echo "- queued: Batch is waiting to start"
echo "- running: Batch is currently fetching emails"
echo "- completed: Batch finished successfully"
echo "- error: Batch failed (check error_message)"
echo "- auth_required: Gmail authentication needed"
echo ""
