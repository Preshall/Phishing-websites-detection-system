from phishing_detector import PhishingDetector

def test_urls():
    # Create detector instance
    detector = PhishingDetector()
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "https://www.microsoft.com",
        "http://suspicious-site.example.com",
        "http://192.168.1.1/login.php"
    ]
    
    print("Testing URLs for phishing detection:\n")
    for url in test_urls:
        try:
            result = detector.predict(url)
            print(f"URL: {url}")
            print(f"Prediction: {'Phishing' if result['is_phishing'] else 'Legitimate'}")
            print(f"Confidence: {result['confidence']:.2f}\n")
        except Exception as e:
            print(f"Error analyzing {url}: {str(e)}\n")

if __name__ == "__main__":
    test_urls()
