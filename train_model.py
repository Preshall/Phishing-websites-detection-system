import pandas as pd
from sklearn.model_selection import train_test_split
from phishing_detector import PhishingDetector

def train_model():
    # Load the dataset
    print("Loading dataset...")
    df = pd.read_csv('phishing_dataset.csv')
    
    # Initialize detector
    detector = PhishingDetector()
    
    # Extract features for all URLs
    print("Extracting features...")
    features_list = []
    for url in df['url']:
        features, feature_array = detector.extract_features(url)
        features_list.append(feature_array[0])
    
    # Convert to numpy array
    X = pd.DataFrame(features_list)
    y = df['is_phishing']
    
    # Split into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train the model
    print("Training model...")
    detector.train(X_train, y_train)
    
    # Evaluate the model
    print("\nModel Evaluation:")
    from sklearn.metrics import accuracy_score, classification_report
    y_pred = detector.model.predict(X_test)
    print("\nAccuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

if __name__ == "__main__":
    train_model()
