import numpy as np
import pytest
from phishguard.ml.features import extract_features

def test_extract_features_shape_and_type():
    url = "https://www.google.com"
    features = extract_features(url)
    
    assert isinstance(features, np.ndarray)
    assert features.shape == (22,)
    assert features.dtype == np.float32
    assert not np.isnan(features).any()
    assert not np.isinf(features).any()

@pytest.mark.parametrize("url, description", [
    ("https://www.google.com", "Benign URL"),
    ("http://login-verify-paypal.com.tk/secure", "Phishing URL"),
    ("http://192.168.1.1/index.php", "IP Address URL"),
    ("https://xn--e1afmkfd.xn--p1ai/", "Punycode URL"),
    ("https://example.com/%20test%20", "Percent-encoded URL"),
    ("a", "Very short URL"),
    ("https://long.subdomain.example.com/path/to/resource?query=1&param=2#frag", "Complex URL")
])
def test_extract_features_various_urls(url, description):
    features = extract_features(url)
    assert features.shape == (22,)
    assert not np.isnan(features).any()

def test_extract_features_specific_logic():
    # Test HTTPS detection
    features_https = extract_features("https://example.com")
    features_http = extract_features("http://example.com")
    
    # has_https is at index 8
    assert features_https[8] == 1.0
    assert features_http[8] == 0.0
    
    # Test IP detection
    features_ip = extract_features("http://1.1.1.1/test")
    # has_ip_address is at index 7
    assert features_ip[7] == 1.0
    
    # Test suspicious keyword count
    # keywords: login, verify, secure, update, confirm, bank, account, password, signin, suspend
    features_kw = extract_features("http://login-verify-secure.com")
    # suspicious_keyword_count is at index 20
    assert features_kw[20] >= 3.0
