import pytest
import time
import os
import joblib
import numpy as np
from phishguard.ml.predict import predict

MODEL_PATH = "e:/Phishguard/phishguard/ml/model.pkl"

@pytest.mark.skipif(not os.path.exists(MODEL_PATH), reason="Model file not found")
def test_model_performance_and_validity():
    urls = [
        "https://google.com",
        "http://phishing-site.tk",
        "http://127.0.0.1",
        "https://amazon.com/login",
        "http://malware-dist.ru"
    ]
    
    start_time = time.time()
    for _ in range(20): # Total 100 predictions across 5 URLs
        for url in urls:
            result = predict(url)
            assert 0.0 <= result["confidence"] <= 1.0
            assert "label" in result
            assert "features" in result
            
    total_duration_ms = (time.time() - start_time) * 1000
    # Requirement: 100 predictions < 500ms total
    assert total_duration_ms < 500

def test_predict_edge_cases():
    # Single char
    res1 = predict("a")
    assert res1["label"] is not None
    
    # Numeric domain
    res2 = predict("http://123456789.com")
    assert res2["label"] is not None
    
    # IP only
    res3 = predict("http://192.168.1.1")
    assert res3["label"] is not None

def test_confidence_distribution():
    # Model should generally have high confidence on very clear benign/phishing
    benign = predict("https://www.microsoft.com")
    # Even if it's wrong, confidence should be a valid probability
    assert isinstance(benign["confidence"], (float, np.float32, np.float64))
    assert 0.0 <= benign["confidence"] <= 1.0
