import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { getStats, getHistory } from '../api/client';
import {
  PieChart, Pie, Cell, Tooltip, Legend,
  AreaChart, Area, XAxis, YAxis, CartesianGrid, ResponsiveContainer,
  BarChart, Bar
} from 'recharts';

const RISK_COLORS = {
  safe: '#10b981', // emerald-500
  low: '#84cc16',  // lime-500
  medium: '#eab308', // yellow-500
  high: '#f97316', // orange-500
  critical: '#ef4444', // red-500
};

const LABEL_COLORS = {
  benign: '#10b981',
  defacement: '#eab308',
  malware: '#f97316',
  phishing: '#ef4444',
};

export default function RiskChart() {
  const { data: stats } = useQuery({
    queryKey: ['stats'],
    queryFn: getStats,
    refetchInterval: 10000,
  });

  const { data: history = [] } = useQuery({
    queryKey: ['history'],
    queryFn: getHistory,
    refetchInterval: 10000,
  });

  if (!stats) {
    return <div className="text-center text-slate-400 py-8">Loading stats...</div>;
  }

  // Format data for PieChart (Risk Distribution)
  const riskData = Object.entries(stats.risk_distribution || {}).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
    color: RISK_COLORS[name] || '#64748b',
  })).filter(d => d.value > 0);

  // Format data for BarChart (Label Distribution)
  const labelData = [
    { name: 'Safe', value: stats.benign_count, color: LABEL_COLORS.benign },
    { name: 'Phishing', value: stats.phishing_count, color: LABEL_COLORS.phishing },
    { name: 'Malware', value: stats.malware_count, color: LABEL_COLORS.malware },
    { name: 'Defacement', value: stats.defacement_count, color: LABEL_COLORS.defacement },
  ].filter(d => d.value > 0);

  // Format data for AreaChart (Recent Scans)
  const timeData = history.slice(0, 50).reverse().map((item, index) => ({
    index: index + 1,
    risk: Math.round(item.risk_score * 100),
    label: item.label
  }));

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-slate-800 border border-slate-700 p-2 rounded shadow-lg text-sm">
          <p className="text-white">{`${payload[0].name || 'Risk'}: ${payload[0].value}`}</p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-[#1e293b] p-6 rounded-xl border border-slate-700/50 shadow-sm col-span-1 md:col-span-3 lg:col-span-1 flex flex-col justify-center">
          <h3 className="text-slate-400 text-sm font-medium uppercase tracking-wider mb-2">Total Scans</h3>
          <p className="text-4xl font-bold text-white">{stats.total}</p>
          <div className="mt-4 space-y-2">
             <div className="flex justify-between text-sm">
               <span className="text-slate-400">Threats Found</span>
               <span className="text-red-400 font-medium">{stats.total - stats.benign_count}</span>
             </div>
             <div className="flex justify-between text-sm">
               <span className="text-slate-400">Safe URLs</span>
               <span className="text-emerald-400 font-medium">{stats.benign_count}</span>
             </div>
          </div>
        </div>

        <div className="bg-[#1e293b] p-6 rounded-xl border border-slate-700/50 shadow-sm flex flex-col items-center">
          <h3 className="text-slate-200 font-medium mb-4 w-full text-left">Risk Distribution</h3>
          {riskData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={riskData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                  stroke="none"
                >
                  {riskData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex-1 flex items-center justify-center text-slate-500">No data</div>
          )}
        </div>

        <div className="bg-[#1e293b] p-6 rounded-xl border border-slate-700/50 shadow-sm flex flex-col items-center">
          <h3 className="text-slate-200 font-medium mb-4 w-full text-left">Threat Types</h3>
          {labelData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={labelData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                <XAxis dataKey="name" tick={{fill: '#94a3b8', fontSize: 12}} axisLine={false} tickLine={false} />
                <YAxis tick={{fill: '#94a3b8', fontSize: 12}} axisLine={false} tickLine={false} />
                <Tooltip cursor={{fill: '#334155', opacity: 0.4}} content={<CustomTooltip />} />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {labelData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex-1 flex items-center justify-center text-slate-500">No data</div>
          )}
        </div>
      </div>

      <div className="bg-[#1e293b] p-6 rounded-xl border border-slate-700/50 shadow-sm">
        <h3 className="text-slate-200 font-medium mb-6">Recent Scans Risk Trend (Last 50)</h3>
        {timeData.length > 0 ? (
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={timeData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#38bdf8" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <XAxis dataKey="index" tick={false} axisLine={false} tickLine={false} />
              <YAxis domain={[0, 100]} tick={{fill: '#94a3b8'}} axisLine={false} tickLine={false} />
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#f8fafc' }}
                formatter={(value, name, props) => [`${value}/100`, 'Risk Score']}
                labelFormatter={() => ''}
              />
              <Area type="monotone" dataKey="risk" stroke="#38bdf8" fillOpacity={1} fill="url(#colorRisk)" />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="h-[300px] flex items-center justify-center text-slate-500">No recent scans</div>
        )}
      </div>
    </div>
  );
}
