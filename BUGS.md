# Known Failure Points & Bugs

### 1. External API Timeouts (CTI/WHOIS)
- **Problem**: `python-whois` can hang for up to 30 seconds if the WHOIS server is unresponsive, blocking the async event loop if not properly wrapped in a thread-pool or process-pool.
- **Impact**: API latency spikes significantly beyond the 500ms target.
- **Fix**: Enforce strict timeouts using `asyncio.wait_for` and run synchronous lookups in `loop.run_in_executor`.

### 2. XGBoost Thread Safety
- **Problem**: While `predict()` is generally safe, concurrent access to the same loaded model instance via `joblib` can occasionally cause memory fragmentation or crashes in high-concurrency environments (FastAPI with multiple workers).
- **Fix**: Use `joblib` with the `mmap_mode='r'` flag to share model weights safely across processes.

### 3. Extension Storage Quota
- **Problem**: `chrome.storage.local` has a default limit (approx 5-10MB). Storing thousands of URL analysis results (including feature dicts) can exceed this.
- **Impact**: Caching fails, causing redundant API calls and potential backend DoS.
- **Fix**: Implement a rotation policy (LRU) in the extension or store only minimal risk data.

### 4. CORS Misconfiguration
- **Problem**: If the dashboard is deployed on a custom domain or a different port than expected, the backend CORS policy (`allow_origins=["*"]`) must be strictly audited for production.
- **Fix**: Explicitly whitelist production domains in `main.py`.

### 5. VirusTotal Rate Limits
- **Problem**: The public API key tier is limited to **4 requests per minute**.
- **Impact**: Real-time scanning will fail for most users after the first few clicks.
- **Fix**: Implement a global API rate limiter in `cti.py` or upgrade to a premium key.

### 6. Unicode/IDN Homographs
- **Problem**: Some punycode URLs (e.g., `apple.com` using Cyrillic 'a') may bypass basic brand impersonation checks if not normalized.
- **Fix**: Use `idna` decoding before running feature extraction.
