import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# Add the current directory to sys.path to import features
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from features import extract_features, FEATURE_NAMES

def normalize_url(url):
    """
    Normalize: strip whitespace, lowercase scheme only.
    Example: HTTPS://example.com/Path -> https://example.com/Path
    """
    url = url.strip()
    if "://" in url:
        parts = url.split("://", 1)
        url = parts[0].lower() + "://" + parts[1]
    return url

def preprocess_data(csv_path="malicious_phish.csv"):
    # 1. Load CSV
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    
    # 2. Basic Cleaning
    print("Dropping nulls and duplicates...")
    df = df.dropna(subset=['url', 'type'])
    df = df.drop_duplicates(subset=['url'])
    
    # 3. Normalization
    print("Normalizing URLs...")
    df['url'] = df['url'].apply(normalize_url)
    
    print("\nClass distribution before split:")
    print(df['type'].value_counts())
    
    # 4. Label Encoding
    print("\nEncoding labels...")
    le = LabelEncoder()
    df['label'] = le.fit_transform(df['type'])
    joblib.dump(le, LE_PATH)
    print(f"Label encoder saved. Classes: {list(le.classes_)}")
    
    # 5. Feature Extraction
    print("\nExtracting features (this may take a few minutes)...")
    urls = df['url'].values
    X = np.zeros((len(urls), len(FEATURE_NAMES)), dtype=np.float32)
    
    for i, url in enumerate(urls):
        features_dict = extract_features(url)
        X[i] = [features_dict[k] for k in FEATURE_NAMES]
        if i % 50000 == 0:
            print(f"Processed {i}/{len(urls)} URLs...")
            
    y = df['label'].values
    
    # 6. Stratified Split
    print("\nPerforming stratified 80/20 split...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # 7. Save Files
    print("Saving processed data...")
    np.save('X_train.npy', X_train)
    np.save('X_test.npy', X_test)
    np.save('y_train.npy', y_train)
    np.save('y_test.npy', y_test)
    
    with open('feature_names.json', 'w') as f:
        json.dump(FEATURE_NAMES, f)
        
    # 8. Report
    print("\nClass distribution in Training set:")
    unique_train, counts_train = np.unique(y_train, return_counts=True)
    for u, c in zip(unique_train, counts_train):
        print(f"  {le.inverse_transform([u])[0]}: {c}")
        
    print("\nClass distribution in Test set:")
    unique_test, counts_test = np.unique(y_test, return_counts=True)
    for u, c in zip(unique_test, counts_test):
        print(f"  {le.inverse_transform([u])[0]}: {c}")
        
    print("\nPreprocessing complete.")
    return X_train, X_test, y_train, y_test, le

_HERE = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(_HERE, "../malicious_phish.csv")
LE_PATH = os.path.join(_HERE, "label_encoder.pkl")
load_and_preprocess = preprocess_data

def load_artefacts():
    X_train = np.load('X_train.npy')
    X_test = np.load('X_test.npy')
    y_train = np.load('y_train.npy')
    y_test = np.load('y_test.npy')
    le = joblib.load(LE_PATH)
    return X_train, X_test, y_train, y_test, le

if __name__ == "__main__":
    if os.path.exists(CSV_PATH):
        preprocess_data(CSV_PATH)
    else:
        # Fallback for local run if archive dir doesn't exist
        local_csv = 'malicious_phish.csv'
        if os.path.exists(local_csv):
            preprocess_data(local_csv)
        else:
            print(f"Error: {CSV_PATH} not found.")
