from flask import Flask, request, render_template
import requests

# Google Safe Browsing API key
API_KEY = "AIzaSyDaO0QPEss23gCDP9ZMJWHKOWZiUwZwmzg"

# Function to check link safety using Google Safe Browsing
def check_safe_browsing(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
    payload = {
        "client": {
            "clientId": "LinkVerifier",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(api_url, json=payload)
    if response.status_code == 200:
        if response.json().get("matches"):
            return False  # Link is unsafe
    return True  # Link is safe

# Flask app setup
app = Flask(__name__)

# Route for home page
@app.route('/')
def home():
    return render_template('index.html')  # Renders the home page

# Route to verify link
@app.route('/verify', methods=['POST'])
def verify():
    url = request.form.get('url')  # Get URL from form
    if url:
        is_safe = check_safe_browsing(url)
        if is_safe:
            result = "Safe: The link is safe to visit."
        else:
            result = "Unsafe: The link is potentially dangerous."
    else:
        result = "Error: Please enter a valid URL."
    return render_template('result.html', url=url, result=result)

if __name__ == "__main__":
    app.run(debug=True)
