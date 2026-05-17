import pytest
import httpx
import time
import asyncio
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from phishguard.backend.main import app

client = TestClient(app)

# Mock external CTI/Forensics calls for speed and stability
@pytest.fixture(autouse=True)
def mock_external_calls():
    with patch("phishguard.backend.main.get_cti", new_callable=AsyncMock) as m_cti, \
         patch("phishguard.backend.main.get_whois", return_value={"age_days": 500, "registrar": "Google"}), \
         patch("phishguard.backend.main.get_dns", return_value={"a_records": ["1.1.1.1"]}):
        
        m_cti.return_value = {
            "virustotal": {"malicious": 0, "status": "ok"},
            "urlhaus": {"url_status": "offline"}
        }
        yield

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_analyze_valid_url():
    start_time = time.time()
    response = client.post("/analyze", json={"url": "https://google.com"})
    duration = (time.time() - start_time) * 1000
    
    assert response.status_code == 200
    data = response.json()
    assert "label" in data
    assert "risk_score" in data
    assert "confidence" in data
    assert duration < 500  # Performance requirement

def test_analyze_edge_cases():
    # Empty URL
    response = client.post("/analyze", json={"url": ""})
    assert response.status_code == 400
    
    # Special chars
    response = client.post("/analyze", json={"url": "https://example.com/!@#$%^&*()"})
    assert response.status_code == 200
    
    # Very long URL
    long_url = "https://example.com/" + ("a" * 2000)
    response = client.post("/analyze", json={"url": long_url})
    assert response.status_code == 200

def test_history_endpoint():
    # Populate history
    client.post("/analyze", json={"url": "https://a.com"})
    client.post("/analyze", json={"url": "https://b.com"})
    
    response = client.get("/history")
    assert response.status_code == 200
    history = response.json()
    assert isinstance(history, list)
    assert len(history) <= 500

def test_stats_endpoint():
    response = client.get("/stats")
    assert response.status_code == 200
    stats = response.json()
    required_keys = {"total", "phishing_count", "benign_count", "risk_distribution"}
    assert all(k in stats for k in required_keys)

def test_cors_headers():
    response = client.options("/analyze", headers={
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "POST"
    })
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "*"
