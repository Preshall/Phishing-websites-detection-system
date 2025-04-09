# Phishing URL Detector

A machine learning-powered web application that detects potentially malicious phishing URLs. The system uses a Random Forest Classifier and analyzes various URL features to determine if a URL is potentially dangerous.

## Features

### Key URL Analysis Features
- Domain-based features (high importance):
  - Domain length
  - Subdomain count
  - Domain age
  - IP address detection
  - Suspicious word detection

### Additional Features (de-emphasized)
- Character-based analysis:
  - Special character count
  - Digit count
  - Letter count
- URL structure analysis:
  - Path length
  - Query parameters
  - Protocol (HTTPS)
  - Special characters

## Project Structure

```
phishing_detector/
├── app.py                 # Flask web application
├── phishing_detector.py   # Core detection logic and ML model
├── generate_dataset.py    # Dataset generation script
├── train_model.py        # Model training script
├── requirements.txt      # Python dependencies
├── templates/
│   └── index.html       # Web interface
└── phishing_model.joblib # Trained ML model
```

## Installation

1. Create a virtual environment:
```bash
python -m venv venv
.\venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Generate the dataset:
```bash
python generate_dataset.py
```

2. Train the model:
```bash
python train_model.py
```

3. Run the web application:
```bash
python app.py
```

4. Open your browser and navigate to `http://localhost:5000`

## Model Details

The system uses a Random Forest Classifier with the following key features:
- Domain age verification
- Domain length analysis
- Subdomain count checking
- Suspicious pattern detection
- Character frequency analysis

## Dependencies

- Flask==3.0.2
- scikit-learn==1.3.0
- numpy==1.24.3
- pandas==2.0.3
- tldextract==5.1.1
- requests==2.31.0
- beautifulsoup4==4.12.3
- python-whois>=0.8.0
- validators==0.22.0
- python-Levenshtein==0.25.0
- joblib==1.3.2

## License

MIT License
