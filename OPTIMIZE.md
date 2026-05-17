# Performance Optimizations

### 1. Model Preloading
- **Optimization**: Ensure `joblib.load()` happens once in the `startup` event of FastAPI.
- **Benefit**: Removes ~50-100ms of disk I/O latency from the request path.

### 2. Feature Extraction LRU Cache
- **Optimization**: Use `functools.lru_cache(maxsize=2048)` on the `extract_features` function.
- **Benefit**: Instant results for frequently visited domains (e.g., Google, Facebook), saving CPU cycles.

### 3. Parallel Execution of CTI
- **Optimization**: Use `asyncio.gather()` in `backend/main.py` to trigger VirusTotal, URLHaus, and DNS lookups concurrently.
- **Benefit**: Total latency becomes `max(CTI, DNS, ML)` instead of `sum(CTI, DNS, ML)`.

### 4. Fast Mode Flag
- **Optimization**: Add an environment variable `FAST_MODE=1`.
- **Logic**: If enabled, skip WHOIS and Deep DNS lookups (which are slow) and rely purely on ML + CTI Cache.
- **Benefit**: Guaranteed <200ms response time.

### 5. Binary Serialization
- **Optimization**: Switch from JSON to MessagePack or Protobuf for internal communication between Extension and Backend.
- **Benefit**: Reduces payload size and parsing overhead.

### 6. Caching Layer (Redis)
- **Optimization**: Add a Redis cache in front of the backend database/history.
- **Benefit**: Scaling to thousands of concurrent users without hitting memory limits on a single node.
