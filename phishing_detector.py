import requests
from bs4 import BeautifulSoup
import tldextract
import whois
import validators
import numpy as np
from urllib.parse import urlparse
import re
import joblib
import os
from datetime import datetime
from Levenshtein import distance

class PhishingDetector:
    def __init__(self):
        """Initialize the PhishingDetector with necessary components."""
        self.model = None
        if os.path.exists('phishing_model.joblib'):
            self.model = joblib.load('phishing_model.joblib')
            
        # Whitelist of known legitimate domains
        self.legitimate_domains = {
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'netflix.com', 'linkedin.com', 'twitter.com',
            'instagram.com', 'youtube.com', 'github.com', 'reddit.com',
            'wikipedia.org', 'yahoo.com', 'ebay.com', 'paypal.com',
            'dropbox.com', 'spotify.com', 'adobe.com', 'salesforce.com',
            'tiktok.com', 'whatsapp.com', 'zoom.us', 'twitch.tv'
        }

    def extract_features(self, url):
        """Extract features from the URL for phishing detection."""
        features = {}
        
        # Parse URL components
        parsed_url = urlparse(url)
        ext = tldextract.extract(url)
        
        # High importance domain-related features (key indicators of legitimacy)
        features['domain_length'] = len(ext.domain)  # Length of domain name
        features['subdomain_count'] = len(ext.subdomain.split('.')) if ext.subdomain else 0  # Number of subdomains
        
        # Domain age (high importance - older domains are typically more trustworthy)
        try:
            domain_info = whois.whois(ext.registered_domain)
            if domain_info.creation_date:
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                domain_age = (datetime.now() - creation_date).days
                features['domain_age'] = domain_age
            else:
                features['domain_age'] = -1
        except:
            features['domain_age'] = -1
        
        # Lower importance character-based features (scaled down by 0.1)
        features['special_char_count'] = len(re.findall(r'[^a-zA-Z0-9\s]', url)) * 0.1
        features['digit_count'] = len(re.findall(r'\d', url)) * 0.1
        features['letter_count'] = len(re.findall(r'[a-zA-Z]', url)) * 0.1
        
        # Additional features (scaled down)
        features['path_length'] = len(parsed_url.path) * 0.1
        features['has_query'] = bool(parsed_url.query) * 0.1
        features['query_length'] = len(parsed_url.query) * 0.1
        features['num_params'] = len(parsed_url.query.split('&')) if parsed_url.query else 0
        features['is_https'] = bool(parsed_url.scheme == 'https') * 0.1
        features['num_underscores'] = url.count('_') * 0.1
        features['num_dots'] = url.count('.') * 0.1
        features['num_hyphens'] = url.count('-') * 0.1
        features['num_percent'] = url.count('%') * 0.1
        features['num_slash'] = url.count('/') * 0.1
        features['num_colon'] = url.count(':') * 0.1
        features['num_semicolon'] = url.count(';') * 0.1
        features['num_at'] = url.count('@') * 0.1
        features['num_ampersand'] = url.count('&') * 0.1
        features['num_equal'] = url.count('=') * 0.1
        
        # High importance security features
        features['is_ip'] = bool(re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ext.domain))
        features['has_suspicious_words'] = bool(re.search(r'(login|signin|verify|secure|account|banking|password)', url.lower()))
        
        # Convert features to numpy array in a specific order, prioritizing domain features
        feature_array = np.array([
            # High importance domain features first
            features['domain_length'],
            features['subdomain_count'],
            features['domain_age'],
            features['is_ip'],
            features['has_suspicious_words'],
            
            # De-emphasized character-based features
            features['special_char_count'],
            features['digit_count'],
            features['letter_count'],
            
            # Other de-emphasized features
            features['path_length'],
            features['has_query'],
            features['query_length'],
            features['num_params'],
            features['is_https'],
            features['num_underscores'],
            features['num_dots'],
            features['num_hyphens'],
            features['num_percent'],
            features['num_slash'],
            features['num_colon'],
            features['num_semicolon'],
            features['num_at'],
            features['num_ampersand'],
            features['num_equal']
        ]).reshape(1, -1)
        
        return features, feature_array
    
    def is_legitimate_domain(self, url):
        """Check if the domain is in the whitelist of legitimate domains."""
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        return domain in self.legitimate_domains

    def predict(self, url):
        """Predict whether a URL is phishing or not."""
        try:
            # First check if it's a known legitimate domain
            if self.is_legitimate_domain(url):
                return {
                    'is_phishing': False,
                    'confidence': 0.99,
                    'features': {'is_legitimate': True}
                }

            features, feature_array = self.extract_features(url)
            
            if not self.model:
                raise Exception("Model not loaded")
            
            prediction = self.model.predict(feature_array)[0]
            probability = self.model.predict_proba(feature_array)[0]
            confidence = probability[1] if prediction == 1 else probability[0]
            
            return {
                'is_phishing': bool(prediction),
                'confidence': float(confidence),
                'features': features
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'is_phishing': None,
                'confidence': 0.0,
                'features': {}
            }
    
    def train(self, X, y):
        """Train the phishing detection model."""
        from sklearn.ensemble import RandomForestClassifier
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X, y)
        
        # Save the model
        joblib.dump(self.model, 'phishing_model.joblib')
        print("Model trained and saved successfully")

def main():
    detector = PhishingDetector()
    
    # Check if we need to train the model
    if not os.path.exists(detector.model_path):
        print("Training new model...")
        if os.path.exists('phishing_dataset.csv'):
            detector.train('phishing_dataset.csv')
        else:
            print("No dataset found. Please run generate_dataset.py first.")
            return
    
    # Test some URLs
    test_urls = [
        "https://www.google.com",
        "http://googlo.com",
        "https://secure-paypal.com",
        "http://facebook.com-login.suspicious.com"
    ]
    
    for url in test_urls:
        result = detector.predict(url)
        print(f"\nTest URL: {url}")
        print(f"Prediction: {'Phishing' if result['is_phishing'] else 'Legitimate'}")
        print(f"Confidence: {result['confidence']:.2f}")
        print("\nFeatures analyzed:")
        for key, value in result['features'].items():
            print(f"{key}: {value}")

if __name__ == "__main__":
    main()
