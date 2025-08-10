from flask import Flask, render_template, render_template_string, request
import joblib
from urllib.parse import urlparse, urlunparse
import re
import datetime
import requests

app = Flask(__name__)

GOOGLE_API_KEY = "AIzaSyApp1Q_iTQssDZiVqhKfe36i08ZKGNliA4"  # <-- replace with your key
model = joblib.load("phishing_model.pkl")

def normalize_url(url):
    url = url.strip().lower()
    parsed = urlparse(url)
    normalized = parsed._replace(query="", fragment="")
    url = urlunparse(normalized)
    if url.endswith("/") and len(url) > len(parsed.scheme) + 3:
        url = url.rstrip("/")
    return url

def is_valid_url(url):
    regex = re.compile(r'^(http|https)://[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})')
    return re.match(regex, url) is not None

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    def c(s, ch): return s.count(ch)
    feats = {
        'qty_dot_url': c(url, '.'), 'qty_hyphen_url': c(url, '-'), 'qty_underline_url': c(url, '_'),
        'qty_slash_url': c(url, '/'), 'qty_questionmark_url': c(url, '?'), 'qty_equal_url': c(url, '='),
        'qty_at_url': c(url, '@'), 'qty_and_url': c(url, '&'), 'qty_exclamation_url': c(url, '!'),
        'qty_comma_url': c(url, ','), 'qty_plus_url': c(url, '+'), 'qty_asterisk_url': c(url, '*'),
        'qty_hashtag_url': c(url, '#'), 'qty_dollar_url': c(url, '$'), 'qty_percent_url': c(url, '%'),
        'length_url': len(url), 'qty_dot_domain': c(domain, '.'), 'qty_hyphen_domain': c(domain, '-'),
        'domain_length': len(domain)
    }
    return [feats[f] for f in feats]

def check_with_google_safe_browsing(url):
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        body = {
            "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        r = requests.post(endpoint, json=body, timeout=5)
        return "matches" in r.json()
    except:
        return None

def log_check(original_url, normalized_url, prediction, confidence, google_flag):
    with open("logs.txt", "a") as f:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"{ts} | URL: {original_url} | Normalized: {normalized_url} | Prediction: {prediction} | Confidence: {confidence}% | Google: {google_flag}\n")

TEMPLATE_SCAN = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Phishing Detector</title>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
<style>
    html, body {height:100%; margin:0;}
    body {
        font-family: 'Poppins', sans-serif;
        background: linear-gradient(270deg, #4f8cff, #639dff 25%, #527abf 50%, #3c5db1 75%, #131a40);
        background-size: 400% 400%;
        color: white;
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
        min-height: 100vh;
    }
    .container {
        background: rgba(255,255,255,0.08);
        padding: 25px;
        border-radius: 10px;
        max-width: 420px;
        width: 95vw;
        text-align: center;
        box-shadow: 0 4px 20px rgba(0,0,0,0.2);
    }
    input[type=text] {width:100%;padding:10px;border:none;border-radius:5px;margin-bottom:15px;}
    button {padding:10px 20px;background:#63b0ff;color:white;border:none;border-radius:5px;cursor:pointer;}
    button:hover {background:#2b5bd9;}
</style>
</head>
<body>
<div class="container">
<h2>Phishing URL Detector</h2>
<p>Enter a website link to check if it might be unsafe</p>
<form method="POST">
<input type="text" name="url" placeholder="https://example.com" required>
<button type="submit">Check URL</button>
</form>
{% if error %}<div style="color:#ffcccc">{{ error }}</div>{% endif %}
{% if result %}
  <div style="margin-top:15px; color:{% if 'Phishing' in result %}#ffb3b3{% else %}#b3ffb3{% endif %}">
  {{ result }}
  {% if confidence %}<small>Confidence: {{ confidence }}%</small>{% endif %}
  <small>Normalized: {{ normalized_url }}</small>
  </div>
{% endif %}
</div>
</body>
</html>
"""

@app.route('/')
def welcome():
    return render_template("welcome.html")

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    result = error = None
    confidence = None
    normalized_url = None
    if request.method == 'POST':
        original_url = request.form.get("url","").strip()
        if not is_valid_url(original_url):
            error = "❌ Please enter a valid URL starting with http:// or https://"
        else:
            normalized_url = normalize_url(original_url)
            features = extract_features(normalized_url)
            proba = model.predict_proba([features])[0]
            pred_idx = model.predict([features])[0]
            ml_result = "Phishing" if pred_idx == 1 else "Legitimate"
            confidence = round(max(proba)*100, 2)
            google_flag = check_with_google_safe_browsing(normalized_url)
            if google_flag is True:
                result = "Phishing — confirmed by Google Safe Browsing"
            elif google_flag is False:
                result = ml_result
            else:
                result = f"{ml_result} (Google check unavailable)"
            log_check(original_url, normalized_url, ml_result, confidence, google_flag)
    return render_template_string(TEMPLATE_SCAN, result=result, error=error, confidence=confidence, normalized_url=normalized_url)

if __name__ == "__main__":
    app.run(debug=True)
