import pandas as pd
import numpy as np
from urllib.parse import urlparse
import tldextract

# List of legitimate domains and their variations
legitimate_urls = [
    "https://www.google.com",
    "https://www.facebook.com",
    "https://www.amazon.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.netflix.com",
    "https://www.linkedin.com",
    "https://www.twitter.com",
    "https://www.instagram.com",
    "https://www.youtube.com",
    # Additional legitimate domains
    "https://www.github.com",
    "https://www.reddit.com",
    "https://www.wikipedia.org",
    "https://www.yahoo.com",
    "https://www.ebay.com",
    "https://www.paypal.com",
    "https://www.dropbox.com",
    "https://www.spotify.com",
    "https://www.adobe.com",
    "https://www.salesforce.com",
    # Add variations of legitimate domains
    "http://google.com",
    "https://facebook.com",
    "https://amazon.com",
    "https://microsoft.com",
    "https://apple.com",
    "http://www.google.com/search",
    "https://www.facebook.com/login",
    "https://www.amazon.com/products",
    "https://www.microsoft.com/windows",
    "https://www.apple.com/iphone"
]

# Generate phishing URLs based on common patterns
def generate_phishing_urls():
    phishing_urls = []
    domains = [urlparse(url).netloc.replace('www.', '') for url in legitimate_urls]
    
    for domain in domains:
        # Typosquatting
        typos = [
            f"https://www.{domain.replace('o', '0')}",
            f"https://www.{domain.replace('i', '1')}",
            f"https://www.{domain.replace('l', '1')}",
            f"http://{domain}",  # HTTP version
            f"https://{domain.replace('.', '-')}"
        ]
        
        # Add common phishing patterns
        phishing_patterns = [
            f"http://login.{domain}.suspicious.com",
            f"http://{domain}.login.com",
            f"http://verify-{domain}.com",
            f"http://secure-{domain}.net",
            f"http://{domain}.account-verify.com",
            f"http://signin.{domain}.phishing.com",
            f"http://{domain}-secure-login.com",
            f"http://account-verification.{domain}.net",
            f"http://password-reset.{domain}.com",
            f"http://{domain}.security-check.com"
        ]
        
        phishing_urls.extend(typos)
        phishing_urls.extend(phishing_patterns)
    
    return phishing_urls

def generate_dataset(output_file='phishing_dataset.csv'):
    # Generate URLs
    phishing_urls = generate_phishing_urls()
    all_urls = legitimate_urls + phishing_urls
    
    # Create labels (0 for legitimate, 1 for phishing)
    labels = [0] * len(legitimate_urls) + [1] * len(phishing_urls)
    
    # Create DataFrame
    df = pd.DataFrame({
        'url': all_urls,
        'is_phishing': labels
    })
    
    # Shuffle the dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Save to CSV
    df.to_csv(output_file, index=False)
    print(f"Dataset generated with {len(df)} URLs ({len(legitimate_urls)} legitimate, {len(phishing_urls)} phishing)")
    return df

if __name__ == "__main__":
    generate_dataset()
