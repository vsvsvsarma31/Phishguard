const BACKEND_URL = "http://localhost:8000/analyze";
const CACHE_TTL = 60 * 60 * 1000; // 1 hour

function shouldSkip(url) {
  if (!url) return true;
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('file://')) return true;
  try {
    const urlObj = new URL(url);
    if (urlObj.hostname === 'localhost' || urlObj.hostname === '127.0.0.1') return true;
  } catch (e) {
    return true;
  }
  return false;
}

async function analyzeUrl(url) {
  if (shouldSkip(url)) return null;

  const cacheKey = `cache_${url}`;
  const data = await chrome.storage.local.get(cacheKey);
  
  // Check Cache
  if (data[cacheKey]) {
    if (Date.now() - data[cacheKey].timestamp < CACHE_TTL) {
      return data[cacheKey].result;
    }
  }

  // Fetch from backend
  try {
    const response = await fetch(BACKEND_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    
    const result = await response.json();
    
    // Cache result
    await chrome.storage.local.set({
      [cacheKey]: { result, timestamp: Date.now() }
    });

    // Save to last 5 scans
    saveToHistory(result);

    return result;
  } catch (err) {
    console.error('Error analyzing URL:', err);
    return null;
  }
}

async function saveToHistory(result) {
  const data = await chrome.storage.local.get('scanHistory');
  let history = data.scanHistory || [];
  
  // Remove existing entry for same URL if it exists
  history = history.filter(item => item.url !== result.url);
  history.unshift(result);
  
  // Keep only last 5
  if (history.length > 5) history.pop();
  await chrome.storage.local.set({ scanHistory: history });
}

// Listen to navigation events
chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only main frame
  
  const result = await analyzeUrl(details.url);
  
  if (result && result.label !== 'benign') {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png', 
      title: 'PhishGuard Alert',
      message: `Detected ${result.label.toUpperCase()} (confidence: ${(result.confidence * 100).toFixed(1)}%). Risk Score: ${(result.risk_score * 100).toFixed(0)}/100`
    });
  }
});

// Listen to messages from popup and content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'analyzeUrl') {
    analyzeUrl(message.url).then(result => {
      sendResponse(result);
    });
    return true; // Keep message channel open for async response
  }
  
  if (message.action === 'getHistory') {
    chrome.storage.local.get('scanHistory').then(data => {
      sendResponse(data.scanHistory || []);
    });
    return true;
  }
});
