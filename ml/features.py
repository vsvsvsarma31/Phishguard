import re
import math
import numpy as np
from urllib.parse import urlparse

# --- Constants ---
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'secure', 'update', 'confirm', 'bank', 'account', 'password', 'signin', 'suspend']

TOP_50_BRANDS = [
    "google", "youtube", "facebook", "amazon", "microsoft", "apple", "netflix", "paypal", "ebay", "twitter", "linkedin",
    "instagram", "yahoo", "whatsapp", "adobe", "bankofamerica", "chase", "wellsfargo", "citibank", "hsbc", "barclays",
    "alibaba", "aliexpress", "baidu", "tencent", "rakuten", "steam", "spotify", "dropbox", "github", "bitly",
    "blockchain", "coinbase", "binance", "discord", "zoom", "slack", "trello", "jira", "canva", "docusign",
    "salesforce", "oracle", "sap", "ibm", "cisco", "intel", "nvidia", "uber", "airbnb", "booking"
]

COMMON_TLDS = {
    'com': 1, 'org': 2, 'net': 3, 'edu': 4, 'gov': 5, 'info': 6, 'biz': 7, 'io': 8, 'me': 9, 'tv': 10,
    'ru': 11, 'de': 12, 'br': 13, 'uk': 14, 'fr': 15, 'it': 16, 'pl': 17, 'in': 18, 'au': 19, 'es': 20
}

IP_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|'  # IPv4
    r'^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}$|'  # IPv6
    r'^([0-9a-fA-F]{1,4}:){1,7}:$|'
    r'^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|'
    r'^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|'
    r'^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|'
    r'^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|'
    r'^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|'
    r'^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$|'
    r'^:((:[0-9a-fA-F]{1,4}){1,7}|:)$|'
    r'^fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}$|'
    r'^::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$|'
    r'^([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$'
)

# --- Helper Functions ---

def shannon_entropy(s):
    if not s:
        return 0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def levenshtein_dist(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_dist(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

# --- Main Feature Extractor ---

SUSPICIOUS_TLDS = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'link', 'online'}
LOGIN_KEYWORDS  = {'login', 'signin', 'verify', 'secure', 'account'}
REDIRECT_PARAMS = {'redirect', 'return', 'next', 'url='}

def extract_features(url):
    """
    Extracts 29 features from a URL string and returns a dict {feature_name: np.float32}.
    22 base features + 7 phishing-vs-benign discriminators.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return {name: np.float32(0.0) for name in FEATURE_NAMES}

    hostname = parsed.hostname if parsed.hostname else ""
    path = parsed.path if parsed.path else ""
    query = parsed.query if parsed.query else ""
    
    # 1. url_length
    url_len = len(url)
    
    # 2-6. Counts
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    num_slashes = url.count('/')
    num_at = url.count('@')
    num_digits = sum(c.isdigit() for c in url)
    
    # 7. num_special
    # Non-alphanumeric excluding common URL chars
    special_chars = re.sub(r'[a-zA-Z0-9\.\-\/@\?&=\+%: _]', '', url)
    num_special = len(special_chars)
    
    # 8. has_ip_address
    has_ip = 1.0 if IP_PATTERN.match(hostname) else 0.0
    
    # 9. has_https
    has_https = 1.0 if parsed.scheme.lower() == 'https' else 0.0
    
    # 10. has_port
    has_port = 1.0 if parsed.port else 0.0
    
    # 11. subdomain_count
    host_parts = hostname.split('.')
    subdomain_count = max(0, len(host_parts) - 2) if host_parts else 0
    
    # 12. domain_length
    domain_len = len(hostname)
    
    # 13. path_length
    path_len = len(path)
    
    # 14. query_param_count
    query_param_count = query.count('=')
    
    # 15. has_hex_encoding
    has_hex = 1.0 if re.search(r'%[0-9a-fA-F]{2}', url) else 0.0
    
    # 16. entropy
    entropy = shannon_entropy(url)
    
    # 17. digit_ratio
    digit_ratio = num_digits / url_len if url_len > 0 else 0
    
    # 18. url_depth
    url_depth = path.count('/')
    
    # 19-20. Brand features
    clean_host = hostname[4:] if hostname.startswith('www.') else hostname
    domain_part = clean_host.split('.')[0] if clean_host else ""
    if domain_part in TOP_50_BRANDS:
        brand_impersonation_score = 0.0
        typosquat_candidate = 0.0
    else:
        min_dist = min(levenshtein_dist(domain_part, brand) for brand in TOP_50_BRANDS) if TOP_50_BRANDS else 999
        brand_impersonation_score = min_dist / max(len(domain_part), 1)
        typosquat_candidate = 1.0 if min_dist in [1, 2] else 0.0
    
    # 21. suspicious_keyword_count
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower())
    
    # 22. tld_encoded
    tld = hostname.split('.')[-1] if '.' in hostname else ""
    tld_encoded = COMMON_TLDS.get(tld.lower(), 0)

    # ── New features (23-29): phishing vs benign discriminators ──────────────

    # 23. has_suspicious_tld
    has_suspicious_tld = 1.0 if tld.lower() in SUSPICIOUS_TLDS else 0.0

    # 24. has_login_path
    path_lower = path.lower()
    has_login_path = 1.0 if any(kw in path_lower for kw in LOGIN_KEYWORDS) else 0.0

    # 25. domain_digit_ratio
    domain_only = host_parts[-2] if len(host_parts) >= 2 else hostname
    domain_digit_ratio = (sum(c.isdigit() for c in domain_only) / len(domain_only)
                          if domain_only else 0.0)

    # 26. path_has_brand  (brand appears in path but NOT in registrable domain)
    registrable = domain_only.lower()
    path_has_brand = 1.0 if any(
        brand in path_lower and brand not in registrable
        for brand in TOP_50_BRANDS
    ) else 0.0

    # 27. subdomain_is_brand  (any brand appears as a subdomain label)
    subdomain_labels = host_parts[:-2] if len(host_parts) > 2 else []
    subdomain_str = ' '.join(subdomain_labels).lower()
    subdomain_is_brand = 1.0 if any(brand in subdomain_str for brand in TOP_50_BRANDS) else 0.0

    # 28. has_redirect_param
    query_lower = query.lower()
    has_redirect_param = 1.0 if any(rp in query_lower for rp in REDIRECT_PARAMS) else 0.0

    # 29. num_subdomains_gt3
    num_subdomains_gt3 = 1.0 if subdomain_count > 3 else 0.0

    features_list = [
        url_len, num_dots, num_hyphens, num_slashes, num_at, num_digits,
        num_special, has_ip, has_https, has_port, subdomain_count,
        domain_len, path_len, query_param_count, has_hex,
        entropy, digit_ratio, url_depth, brand_impersonation_score,
        typosquat_candidate, suspicious_keyword_count, tld_encoded,
        # new
        has_suspicious_tld, has_login_path, domain_digit_ratio,
        path_has_brand, subdomain_is_brand, has_redirect_param, num_subdomains_gt3,
    ]
    
    return {name: np.float32(val) for name, val in zip(FEATURE_NAMES, features_list)}

FEATURE_NAMES = [
    # base 22
    "url_length", "num_dots", "num_hyphens", "num_slashes", "num_at", "num_digits",
    "num_special", "has_ip_address", "has_https", "has_port", "subdomain_count",
    "domain_length", "path_length", "query_param_count", "has_hex_encoding",
    "entropy", "digit_ratio", "url_depth", "brand_impersonation_score",
    "typosquat_candidate", "suspicious_keyword_count", "tld_encoded",
    # phishing vs benign discriminators (+7)
    "has_suspicious_tld", "has_login_path", "domain_digit_ratio",
    "path_has_brand", "subdomain_is_brand", "has_redirect_param", "num_subdomains_gt3",
]
