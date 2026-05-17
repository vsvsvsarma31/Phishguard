(async function() {
  const currentUrl = window.location.href;

  chrome.runtime.sendMessage({ action: 'analyzeUrl', url: currentUrl }, (result) => {
    if (result && result.label !== 'benign') {
      injectBanner(result);
    }
  });

  function injectBanner(result) {
    if (document.getElementById('phishguard-warning-banner')) return;

    const banner = document.createElement('div');
    banner.id = 'phishguard-warning-banner';
    
    // Style based on label
    let bgColor = '#ef4444'; // red-500 (phishing)
    if (result.label === 'defacement') bgColor = '#eab308'; // yellow-500
    if (result.label === 'malware') bgColor = '#f97316'; // orange-500

    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      background-color: ${bgColor};
      color: white;
      text-align: center;
      padding: 12px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 14px;
      font-weight: 600;
      z-index: 2147483647;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      display: flex;
      justify-content: space-between;
      align-items: center;
    `;

    const text = document.createElement('span');
    text.textContent = `🚨 PhishGuard: ${result.label.toUpperCase()} detected (confidence: ${(result.confidence * 100).toFixed(1)}%) - Risk Score: ${(result.risk_score * 100).toFixed(0)}/100`;
    
    const dismissBtn = document.createElement('button');
    dismissBtn.textContent = 'Dismiss';
    dismissBtn.style.cssText = `
      background: rgba(0,0,0,0.2);
      border: none;
      color: white;
      padding: 4px 12px;
      border-radius: 4px;
      cursor: pointer;
      font-weight: bold;
      margin-right: 20px;
    `;
    dismissBtn.onclick = () => {
      banner.remove();
      document.body.style.marginTop = '0px';
    };

    banner.appendChild(text);
    banner.appendChild(dismissBtn);

    // Push body down
    document.body.style.marginTop = '48px';
    document.documentElement.appendChild(banner);
  }
})();
