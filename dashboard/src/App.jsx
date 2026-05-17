import React, { useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import URLScanner from './components/URLScanner';
import ScanHistory from './components/ScanHistory';
import RiskChart from './components/RiskChart';
import ThreatReport from './components/ThreatReport';

const queryClient = new QueryClient();

function Dashboard() {
  const [activeTab, setActiveTab] = useState('scanner');

  const navItems = [
    { id: 'scanner', label: 'Scanner' },
    { id: 'history', label: 'History' },
    { id: 'stats', label: 'Stats' },
    { id: 'reports', label: 'Reports' },
  ];

  return (
    <div className="min-h-screen bg-[#0f172a] text-slate-200 font-sans selection:bg-[#38bdf8] selection:text-white">
      <nav className="bg-[#1e293b] border-b border-slate-700/50 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <span className="text-2xl">🛡️</span>
              <span className="text-xl font-bold text-white tracking-tight">PhishGuard</span>
            </div>
            <div className="flex space-x-2">
              {navItems.map((item) => (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                    activeTab === item.id
                      ? 'bg-[#38bdf8]/10 text-[#38bdf8]'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                  }`}
                >
                  {item.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'scanner' && <URLScanner />}
        {activeTab === 'history' && <ScanHistory />}
        {activeTab === 'stats' && <RiskChart />}
        {activeTab === 'reports' && <ThreatReport />}
      </main>
    </div>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Dashboard />
    </QueryClientProvider>
  );
}
