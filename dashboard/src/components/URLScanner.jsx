import React, { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { analyzeURL } from '../api/client';

const RISK_COLORS = {
  benign: 'bg-emerald-500 text-emerald-50',
  defacement: 'bg-yellow-500 text-yellow-50',
  malware: 'bg-orange-500 text-orange-50',
  phishing: 'bg-red-500 text-red-50',
  unknown: 'bg-slate-500 text-slate-50',
};

const RISK_BORDER = {
  benign: 'border-emerald-500/30',
  defacement: 'border-yellow-500/30',
  malware: 'border-orange-500/30',
  phishing: 'border-red-500/30',
  unknown: 'border-slate-500/30',
};

export default function URLScanner() {
  const [url, setUrl] = useState('');
  const queryClient = useQueryClient();

  const analyzeMutation = useMutation({
    mutationFn: analyzeURL,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['history'] });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    if (url.trim()) {
      analyzeMutation.mutate(url.trim());
    }
  };

  const result = analyzeMutation.data;

  return (
    <div className="space-y-6">
      <div className="bg-[#1e293b] p-6 rounded-xl border border-slate-700/50 shadow-sm">
        <h2 className="text-lg font-semibold text-white mb-4">Analyze URL</h2>
        <form onSubmit={handleSubmit} className="flex gap-4">
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            required
            className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-4 py-2.5 text-white placeholder-slate-400 focus:outline-none focus:border-[#38bdf8] focus:ring-1 focus:ring-[#38bdf8] transition-colors"
          />
          <button
            type="submit"
            disabled={analyzeMutation.isPending}
            className="bg-[#38bdf8] hover:bg-[#0284c7] text-white px-6 py-2.5 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {analyzeMutation.isPending ? (
              <>
                <svg className="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Scanning...
              </>
            ) : (
              'Analyze'
            )}
          </button>
        </form>
        {analyzeMutation.isError && (
          <div className="mt-4 p-3 bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg text-sm">
            Error analyzing URL: {analyzeMutation.error.message}
          </div>
        )}
      </div>

      {result && (
        <div className={`bg-[#1e293b] p-6 rounded-xl border ${RISK_BORDER[result.label] || RISK_BORDER.unknown} shadow-sm transition-all`}>
          <div className="flex items-start justify-between mb-6">
            <div>
              <h3 className="text-xl font-bold text-white mb-1 break-all">{result.url}</h3>
              <p className="text-slate-400 text-sm">Scanned at {new Date(result.timestamp).toLocaleString()}</p>
            </div>
            <div className={`px-4 py-1.5 rounded-full text-sm font-bold uppercase tracking-wider ${RISK_COLORS[result.label] || RISK_COLORS.unknown}`}>
              {result.label === 'benign' ? 'Safe' : result.label}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-slate-400">Risk Score</span>
                  <span className="text-white font-medium">{(result.risk_score * 100).toFixed(1)}/100</span>
                </div>
                <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${result.risk_score > 0.5 ? 'bg-red-500' : 'bg-[#38bdf8]'}`}
                    style={{ width: `${result.risk_score * 100}%` }}
                  ></div>
                </div>
              </div>
              
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-slate-400">Model Confidence</span>
                  <span className="text-white font-medium">{(result.confidence * 100).toFixed(1)}%</span>
                </div>
                <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-emerald-500"
                    style={{ width: `${result.confidence * 100}%` }}
                  ></div>
                </div>
              </div>
            </div>

            <div className="bg-slate-800/50 rounded-lg p-4 text-sm">
              <h4 className="text-slate-300 font-semibold mb-3 border-b border-slate-700 pb-2">Threat Intelligence</h4>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-slate-400">Obfuscated:</span>
                  <span className={result.is_obfuscated ? 'text-orange-400' : 'text-emerald-400'}>
                    {result.is_obfuscated ? 'Yes' : 'No'}
                  </span>
                </div>
                {result.typosquat_matches?.length > 0 && (
                  <div className="flex justify-between">
                    <span className="text-slate-400">Typosquatting:</span>
                    <span className="text-red-400">{result.typosquat_matches.join(', ')}</span>
                  </div>
                )}
                {result.cti?.virustotal?.malicious > 0 && (
                  <div className="flex justify-between">
                    <span className="text-slate-400">VT Malicious:</span>
                    <span className="text-red-400">{result.cti.virustotal.malicious} hits</span>
                  </div>
                )}
                {result.whois_info?.age_days !== null && result.whois_info?.age_days !== undefined && (
                  <div className="flex justify-between">
                    <span className="text-slate-400">Domain Age:</span>
                    <span className={result.whois_info.age_days < 30 ? 'text-orange-400' : 'text-slate-200'}>
                      {result.whois_info.age_days} days
                    </span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
