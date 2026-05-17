import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getHistory } from '../api/client';

const ROW_COLORS = {
  benign: 'border-l-4 border-emerald-500',
  defacement: 'border-l-4 border-yellow-500',
  malware: 'border-l-4 border-orange-500',
  phishing: 'border-l-4 border-red-500',
};

const TEXT_COLORS = {
  benign: 'text-emerald-400',
  defacement: 'text-yellow-400',
  malware: 'text-orange-400',
  phishing: 'text-red-400',
};

export default function ScanHistory() {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterLabel, setFilterLabel] = useState('ALL');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 20;

  const { data: history = [], isLoading, isError } = useQuery({
    queryKey: ['history'],
    queryFn: getHistory,
    refetchInterval: 10000,
  });

  if (isLoading) {
    return <div className="text-slate-400 text-center py-8">Loading history...</div>;
  }

  if (isError) {
    return <div className="text-red-400 bg-red-500/10 p-4 rounded-lg text-center">Failed to load scan history.</div>;
  }

  const filteredHistory = history.filter((item) => {
    const matchesSearch = item.url.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesFilter = filterLabel === 'ALL' || item.label.toUpperCase() === filterLabel;
    return matchesSearch && matchesFilter;
  });

  const totalPages = Math.ceil(filteredHistory.length / itemsPerPage);
  const paginatedHistory = filteredHistory.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  return (
    <div className="bg-[#1e293b] rounded-xl border border-slate-700/50 shadow-sm overflow-hidden">
      <div className="p-4 border-b border-slate-700/50 flex flex-col sm:flex-row gap-4 justify-between items-center bg-slate-800/30">
        <h2 className="text-lg font-semibold text-white">Scan History</h2>
        <div className="flex gap-2 w-full sm:w-auto">
          <input
            type="text"
            placeholder="Search URLs..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            className="flex-1 sm:w-64 bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-slate-400 focus:outline-none focus:border-[#38bdf8]"
          />
          <select
            value={filterLabel}
            onChange={(e) => {
              setFilterLabel(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-[#38bdf8]"
          >
            <option value="ALL">All Labels</option>
            <option value="BENIGN">Benign</option>
            <option value="PHISHING">Phishing</option>
            <option value="MALWARE">Malware</option>
            <option value="DEFACEMENT">Defacement</option>
          </select>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm whitespace-nowrap">
          <thead className="bg-slate-800/80 text-slate-400">
            <tr>
              <th className="px-6 py-3 font-medium">Timestamp</th>
              <th className="px-6 py-3 font-medium w-full">URL</th>
              <th className="px-6 py-3 font-medium">Label</th>
              <th className="px-6 py-3 font-medium text-right">Risk Score</th>
              <th className="px-6 py-3 font-medium text-right">Confidence</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700/50">
            {paginatedHistory.map((item, idx) => (
              <tr key={idx} className={`hover:bg-slate-800/50 transition-colors ${ROW_COLORS[item.label] || 'border-l-4 border-slate-500'}`}>
                <td className="px-6 py-3 text-slate-400">
                  {new Date(item.timestamp).toLocaleString()}
                </td>
                <td className="px-6 py-3 text-slate-200 font-mono text-xs truncate max-w-[300px] lg:max-w-md" title={item.url}>
                  {item.url.length > 60 ? item.url.substring(0, 60) + '...' : item.url}
                </td>
                <td className={`px-6 py-3 font-semibold uppercase tracking-wider text-xs ${TEXT_COLORS[item.label] || 'text-slate-400'}`}>
                  {item.label}
                </td>
                <td className="px-6 py-3 text-right text-slate-300">
                  {(item.risk_score * 100).toFixed(0)}
                </td>
                <td className="px-6 py-3 text-right text-slate-400">
                  {(item.confidence * 100).toFixed(1)}%
                </td>
              </tr>
            ))}
            {paginatedHistory.length === 0 && (
              <tr>
                <td colSpan="5" className="px-6 py-8 text-center text-slate-500">
                  No scan history found matching criteria.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="p-4 border-t border-slate-700/50 flex justify-between items-center bg-slate-800/30">
          <span className="text-sm text-slate-400">
            Page {currentPage} of {totalPages}
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="px-3 py-1 bg-slate-700 text-white rounded text-sm disabled:opacity-50 hover:bg-slate-600 transition-colors"
            >
              Previous
            </button>
            <button
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="px-3 py-1 bg-slate-700 text-white rounded text-sm disabled:opacity-50 hover:bg-slate-600 transition-colors"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
