from flask import Flask, render_template, request, jsonify
from phishing_detector import PhishingDetector
import json
from datetime import datetime

app = Flask(__name__)
detector = PhishingDetector()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form.get('url', '')
    if not url:
        return jsonify({'error': 'No URL provided'})
    
    try:
        result = detector.predict(url)
        result['url'] = url
        result['timestamp'] = datetime.now().isoformat()
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
