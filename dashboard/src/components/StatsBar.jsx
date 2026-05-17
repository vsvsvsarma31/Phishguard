import React from "react";

function StatCard({ icon, label, value, sub, color }) {
  return (
    <div className="glass rounded-xl p-4 flex items-center gap-4 glass-hover transition-all duration-200">
      <div className="w-10 h-10 rounded-lg flex items-center justify-center text-lg"
           style={{ background: `${color}18` }}>
        {icon}
      </div>
      <div>
        <div className="text-xl font-bold text-white">{value}</div>
        <div className="text-xs text-slate-400">{label}</div>
        {sub && <div className="text-xs mt-0.5" style={{ color }}>{sub}</div>}
      </div>
    </div>
  );
}

export default function StatsBar({ stats }) {
  if (!stats) return null;

  const threatPct = stats.total_scans > 0
    ? ((stats.threats_detected / stats.total_scans) * 100).toFixed(1)
    : 0;

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8 animate-fade-in">
      <StatCard icon="🔍" label="Total Scans" value={stats.total_scans} color="#3b82f6" />
      <StatCard icon="🚨" label="Threats Found" value={stats.threats_detected}
                sub={`${threatPct}% threat rate`} color="#ef4444" />
      <StatCard icon="📊" label="Avg Risk Score" value={stats.avg_risk_score}
                sub={stats.avg_risk_score < 30 ? "Low risk" : stats.avg_risk_score < 60 ? "Moderate" : "High risk"}
                color={stats.avg_risk_score < 30 ? "#22c55e" : stats.avg_risk_score < 60 ? "#f97316" : "#ef4444"} />
      <StatCard icon="🛡️" label="Benign Rate"
                value={`${stats.total_scans > 0 ? (((stats.total_scans - stats.threats_detected) / stats.total_scans) * 100).toFixed(0) : 0}%`}
                color="#22c55e" />
    </div>
  );
}
