document.addEventListener('DOMContentLoaded', async () => {
  const loading = document.getElementById('loading');
  const resultPanel = document.getElementById('result-panel');
  
  // Elements
  const urlDisplay = document.getElementById('url-display');
  const riskBadge = document.getElementById('risk-badge');
  const confidenceVal = document.getElementById('confidence-val');
  const riskVal = document.getElementById('risk-val');
  const featuresList = document.getElementById('features-list');
  const historyList = document.getElementById('history-list');
  
  // Buttons
  document.getElementById('btn-scan-again').addEventListener('click', () => {
    analyzeCurrentTab(true);
  });
  
  document.getElementById('btn-view-report').addEventListener('click', () => {
    chrome.tabs.create({ url: 'http://localhost:5173' });
  });

  async function loadHistory() {
    chrome.runtime.sendMessage({ action: 'getHistory' }, (history) => {
      historyList.innerHTML = '';
      if (!history || history.length === 0) {
        historyList.innerHTML = '<div class="history-item text-slate-400" style="justify-content: center;">No recent scans</div>';
        return;
      }
      
      history.forEach(item => {
        const div = document.createElement('div');
        div.className = 'history-item';
        
        const labelClass = item.label === 'benign' ? 'text-green' : 
                           item.label === 'defacement' ? 'text-yellow' : 
                           item.label === 'malware' ? 'text-orange' : 'text-red';
                           
        div.innerHTML = `
          <div class="history-url truncate" title="${item.url}">${item.url}</div>
          <div class="history-label ${labelClass}">${item.label.toUpperCase()}</div>
        `;
        historyList.appendChild(div);
      });
    });
  }

  async function analyzeCurrentTab(force = false) {
    loading.classList.remove('hidden');
    resultPanel.classList.add('hidden');
    
    // Clear cache if forced
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) {
      showError("Cannot analyze this page.");
      return;
    }
    
    if (force) {
      await chrome.storage.local.remove(`cache_${tab.url}`);
    }
    
    chrome.runtime.sendMessage({ action: 'analyzeUrl', url: tab.url }, (result) => {
      if (!result) {
        showError("Analysis skipped or failed.");
        return;
      }
      displayResult(result);
      loadHistory();
    });
  }

  function showError(msg) {
    loading.classList.add('hidden');
    resultPanel.classList.remove('hidden');
    urlDisplay.textContent = 'Error';
    riskBadge.textContent = 'N/A';
    riskBadge.className = 'badge bg-slate';
    confidenceVal.textContent = '-';
    riskVal.textContent = '-';
    featuresList.innerHTML = `<li>${msg}</li>`;
  }

  function displayResult(result) {
    loading.classList.add('hidden');
    resultPanel.classList.remove('hidden');
    
    urlDisplay.textContent = result.url;
    urlDisplay.title = result.url;
    
    riskBadge.textContent = result.label.toUpperCase();
    
    let badgeClass = 'bg-red';
    if (result.label === 'benign') badgeClass = 'bg-green';
    else if (result.label === 'defacement') badgeClass = 'bg-yellow';
    else if (result.label === 'malware') badgeClass = 'bg-orange';
    
    riskBadge.className = `badge ${badgeClass}`;
    
    confidenceVal.textContent = `${(result.confidence * 100).toFixed(1)}%`;
    riskVal.textContent = `${(result.risk_score * 100).toFixed(0)}/100`;
    
    // Top 3 features
    featuresList.innerHTML = '';
    const features = result.features || {};
    
    // Pick interesting non-zero features
    const interesting = Object.entries(features)
      .filter(([k, v]) => v > 0 && typeof v === 'number' && !k.startsWith('tld_') && k !== 'url_length' && k !== 'domain_length')
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3);
      
    if (interesting.length === 0) {
      featuresList.innerHTML = '<li class="text-slate-400">No highly suspicious features</li>';
    } else {
      interesting.forEach(([key, val]) => {
        const li = document.createElement('li');
        li.textContent = `${key}: ${Number.isInteger(val) ? val : val.toFixed(2)}`;
        featuresList.appendChild(li);
      });
    }
  }

  // Init
  analyzeCurrentTab();
  loadHistory();
});
