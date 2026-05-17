/**
 * @jest-environment jsdom
 */

// Mock Chrome Extension API
global.chrome = {
  storage: {
    local: {
      get: jest.fn(),
      set: jest.fn(),
      remove: jest.fn()
    }
  },
  runtime: {
    sendMessage: jest.fn(),
    onMessage: {
      addListener: jest.fn()
    }
  },
  notifications: {
    create: jest.fn()
  },
  tabs: {
    query: jest.fn(),
    create: jest.fn()
  },
  webNavigation: {
    onCompleted: {
      addListener: jest.fn()
    }
  }
};

// Simple Mock of background.js logic for testing
const CACHE_TTL = 3600000; // 1 hour

async function analyzeUrlWithCache(url, fetchMock) {
  const cacheKey = `cache_${url}`;
  
  // 1. Check Cache
  const cached = await new Promise(resolve => {
    chrome.storage.local.get(cacheKey, (data) => resolve(data[cacheKey]));
  });

  if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
    return cached.result;
  }

  // 2. Fetch
  const result = await fetchMock(url);
  
  // 3. Save Cache
  await chrome.storage.local.set({
    [cacheKey]: { result, timestamp: Date.now() }
  });
  
  return result;
}

function shouldSkip(url) {
  if (!url) return true;
  if (url.startsWith('chrome://')) return true;
  if (url.includes('localhost') || url.includes('127.0.0.1')) return true;
  return false;
}

describe('PhishGuard Extension Logic', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('Cache Hit Logic', async () => {
    const url = 'https://safe.com';
    const mockResult = { label: 'benign' };
    
    // Setup cache hit
    chrome.storage.local.get.mockImplementation((key, cb) => {
      cb({ [`cache_${url}`]: { result: mockResult, timestamp: Date.now() } });
    });

    const fetchMock = jest.fn();
    const result = await analyzeUrlWithCache(url, fetchMock);

    expect(result).toEqual(mockResult);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('Cache Miss / Fetch Logic', async () => {
    const url = 'https://new-site.com';
    const mockResult = { label: 'phishing' };
    
    // Setup cache miss
    chrome.storage.local.get.mockImplementation((key, cb) => cb({}));
    const fetchMock = jest.fn().mockResolvedValue(mockResult);

    const result = await analyzeUrlWithCache(url, fetchMock);

    expect(result).toEqual(mockResult);
    expect(fetchMock).toHaveBeenCalledWith(url);
    expect(chrome.storage.local.set).toHaveBeenCalled();
  });

  test('URL Skip List', () => {
    expect(shouldSkip('chrome://settings')).toBe(true);
    expect(shouldSkip('http://localhost:8000')).toBe(true);
    expect(shouldSkip('http://127.0.0.1/admin')).toBe(true);
    expect(shouldSkip('https://google.com')).toBe(false);
  });

  test('Notification trigger on non-benign', () => {
    // Logic from background.js
    const notifyIfMalicious = (result) => {
      if (result && result.label !== 'benign') {
        chrome.notifications.create({ title: 'Alert', message: 'Risk detected' });
      }
    };

    notifyIfMalicious({ label: 'phishing' });
    expect(chrome.notifications.create).toHaveBeenCalled();

    jest.clearAllMocks();
    notifyIfMalicious({ label: 'benign' });
    expect(chrome.notifications.create).not.toHaveBeenCalled();
  });
});
