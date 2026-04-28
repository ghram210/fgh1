import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { cn } from "@/lib/utils";

const VulnDashboard = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [filterRating, setFilterRating] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [showRatingDrop, setShowRatingDrop] = useState(false);
  const [showStatusDrop, setShowStatusDrop] = useState(false);

  const { data: kpiMttr } = useQuery({
    queryKey: ["kpi-mttr"],
    queryFn: async () => {
      const { data } = await supabase.from("dash_kpi_mttr" as any).select("*").single();
      return data as any;
    },
  });

  const { data: kpiWeaponized } = useQuery({
    queryKey: ["kpi-weaponized"],
    queryFn: async () => {
      const { data } = await supabase.from("dash_kpi_weaponized" as any).select("*").single();
      return data as any;
    },
  });

  const { data: kpiCompliance } = useQuery({
    queryKey: ["kpi-compliance"],
    queryFn: async () => {
      const { data } = await supabase.from("dash_kpi_compliance" as any).select("*").single();
      return data as any;
    },
  });

  const { data: kpiRiskTotal } = useQuery({
    queryKey: ["kpi-risk-total"],
    queryFn: async () => {
      const { data } = await supabase.from("dash_kpi_risk_total" as any).select("*").single();
      return data as any;
    },
  });

  const { data: ratings } = useQuery({
    queryKey: ["vuln-ratings"],
    queryFn: async () => {
      const { data } = await supabase.from("vuln_rating_overview").select("*").order("sort_order");
      return data || [];
    },
  });

  const { data: statuses } = useQuery({
    queryKey: ["vuln-statuses"],
    queryFn: async () => {
      const { data } = await supabase.from("vuln_status_overview").select("*").order("sort_order");
      return data || [];
    },
  });

  const { data: daily } = useQuery({
    queryKey: ["vuln-daily"],
    queryFn: async () => {
      const { data } = await supabase.from("vuln_daily_open").select("*").order("day");
      return data || [];
    },
  });

  const { data: riskScores } = useQuery({
    queryKey: ["vuln-risk"],
    queryFn: async () => {
      const { data } = await supabase.from("vuln_risk_score").select("*").order("sort_order");
      return data || [];
    },
  });

  const { data: byStatus } = useQuery({
    queryKey: ["vuln-by-status"],
    queryFn: async () => {
      const { data } = await supabase.from("vuln_by_status").select("*").order("sort_order");
      return data || [];
    },
  });

  const { data: byExploit } = useQuery({
    queryKey: ["vuln-by-exploit"],
    queryFn: async () => {
      const { data } = await supabase.from("vuln_by_exploit").select("*").order("sort_order");
      return data || [];
    },
  });

  const { data: remOpen } = useQuery({
    queryKey: ["remediation-open"],
    queryFn: async () => {
      const { data } = await supabase.from("remediation_open" as any).select("*").order("sort_order");
      return (data as any[]) || [];
    },
  });

  const { data: remClosed } = useQuery({
    queryKey: ["remediation-closed"],
    queryFn: async () => {
      const { data } = await supabase.from("remediation_closed" as any).select("*").order("sort_order");
      return (data as any[]) || [];
    },
  });

  // Filter ratings cards
  const filteredRatings = (ratings || []).filter((r) => {
    if (filterRating !== "all" && r.label !== filterRating) return false;
    return true;
  });

  // Filter status cards
  const filteredStatuses = (statuses || []).filter((s) => {
    if (filterStatus !== "all" && s.label !== filterStatus) return false;
    return true;
  });

  const totalResults = (ratings || []).reduce((s, r) => s + r.value, 0);
  const totalRisk = (riskScores || []).reduce((s, r) => s + r.value, 0);

  const ratingOptions = ["All Ratings", "Critical", "High", "Medium", "Low"];
  const statusOptions = ["All Status", "Open", "In Progress", "Closed", "Suppressed"];

  const closeAllDrops = () => { setShowRatingDrop(false); setShowStatusDrop(false); };

  return (
    <div className="flex h-screen bg-background text-foreground">
      <AppSidebar collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)} activePage="vuln-dashboard" />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6">
          {/* Tabs */}
          <div className="flex gap-1 mb-4">
            <button className="px-4 py-2 text-sm rounded-t-lg bg-card border border-border border-b-0 text-primary font-medium">
              Overview (CVSS)
            </button>
            <button className="px-4 py-2 text-sm rounded-t-lg text-muted-foreground hover:text-foreground">
              Overview (ExPRT rating)
            </button>
          </div>

          {/* Filters */}
          <div className="flex items-center gap-4 mb-6">
            <span className="text-sm text-muted-foreground">Filter by:</span>

            {/* Rating filter */}
            <div className="relative">
              <button
                onClick={() => { closeAllDrops(); setShowRatingDrop(!showRatingDrop); }}
                className="flex items-center gap-2 px-3 py-1.5 text-sm bg-card border border-border rounded-lg"
              >
                {filterRating === "all" ? "All Ratings" : filterRating}
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
              </button>
              {showRatingDrop && (
                <div className="absolute z-10 mt-1 bg-card border border-border rounded-lg shadow-lg py-1 min-w-[140px]">
                  {ratingOptions.map((opt) => {
                    const val = opt === "All Ratings" ? "all" : opt;
                    const active = filterRating === val;
                    return (
                      <button
                        key={opt}
                        onClick={() => { setFilterRating(val); setShowRatingDrop(false); }}
                        className={cn("w-full text-left px-3 py-1.5 text-sm hover:bg-accent", active ? "bg-primary text-primary-foreground" : "")}
                      >
                        {opt} {active && "✓"}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Status filter */}
            <div className="relative">
              <button
                onClick={() => { closeAllDrops(); setShowStatusDrop(!showStatusDrop); }}
                className="flex items-center gap-2 px-3 py-1.5 text-sm bg-card border border-border rounded-lg"
              >
                {filterStatus === "all" ? "All Status" : filterStatus}
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
              </button>
              {showStatusDrop && (
                <div className="absolute z-10 mt-1 bg-card border border-border rounded-lg shadow-lg py-1 min-w-[140px]">
                  {statusOptions.map((opt) => {
                    const val = opt === "All Status" ? "all" : opt;
                    const active = filterStatus === val;
                    return (
                      <button
                        key={opt}
                        onClick={() => { setFilterStatus(val); setShowStatusDrop(false); }}
                        className={cn("w-full text-left px-3 py-1.5 text-sm hover:bg-accent", active ? "bg-primary text-primary-foreground" : "")}
                      >
                        {opt} {active && "✓"}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            <span className="ml-auto text-sm text-muted-foreground">{totalResults} results</span>
          </div>

          {/* Dashboard KPIs */}
          <h3 className="text-base font-semibold mb-3">Executive Security Metrics</h3>
          <div className="grid grid-cols-4 gap-4 mb-8">
            {[kpiMttr, kpiWeaponized, kpiCompliance, kpiRiskTotal].map((kpi, idx) => (
              <div key={idx} className="bg-card border border-border rounded-xl p-4">
                <div className="flex justify-between items-start mb-1">
                  <span className="text-sm font-medium text-muted-foreground">{kpi?.label || "Loading..."}</span>
                  <span className="text-xs text-muted-foreground">{kpi?.unit}</span>
                </div>
                <p className="text-3xl font-bold mb-3" style={{ color: kpi?.color }}>
                  {kpi?.value ?? 0}
                </p>
                <div className="h-1 rounded-full bg-muted">
                  <div
                    className="h-1 rounded-full"
                    style={{
                      width: kpi?.label === 'Compliance' ? `${kpi?.value}%` : '100%',
                      backgroundColor: kpi?.color
                    }}
                  />
                </div>
              </div>
            ))}
          </div>


          {/* Status Overview */}
          <h3 className="text-base font-semibold mb-3">Vulnerability Status Overview</h3>
          <div className="grid grid-cols-4 gap-4 mb-8">
            {filteredStatuses.map((s) => (
              <div key={s.id} className="bg-card border border-border rounded-xl p-4">
                <div className="flex justify-between items-start mb-1">
                  <span className="text-sm font-medium" style={{ color: s.color }}>{s.label}</span>
                  <span className="text-xs text-muted-foreground">{s.percentage}%</span>
                </div>
                <p className="text-3xl font-bold mb-3" style={{ color: s.color }}>{s.value}</p>
                <div className="h-1 rounded-full bg-muted">
                  <div className="h-1 rounded-full" style={{ width: `${Math.max(s.percentage, 2)}%`, backgroundColor: s.color }} />
                </div>
              </div>
            ))}
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-2 gap-4 mb-8">
            <div className="bg-card border border-border rounded-xl p-5">
              <h3 className="text-sm font-semibold mb-4">Open vulnerabilities by day · Last 45 days</h3>
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={daily || []}>
                  <XAxis dataKey="day" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} labelFormatter={(v) => `Day ${v}`} />
                  <Line type="monotone" dataKey="count" stroke="hsl(var(--primary))" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
            <div className="bg-card border border-border rounded-xl p-5">
              <h3 className="text-sm font-semibold mb-4">Risk Score · CVSS + Exploitability + Asset Criticality + Exposure</h3>
              <div className="flex flex-col items-center">
                <GaugeChart value={totalRisk} />
                <div className="flex flex-wrap gap-4 mt-4 justify-center">
                  {(riskScores || []).map((r) => (
                    <div key={r.id} className="flex items-center gap-1.5 text-xs">
                      <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: r.color }} />
                      <span className="text-muted-foreground">{r.label}</span>
                      <span className="font-medium" style={{ color: r.color }}>{r.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Bar Charts Row */}
          <div className="grid grid-cols-2 gap-4 mb-8">
            <BarSection title="By Status" data={byStatus || []} />
            <BarSection title="By Exploit Status" data={byExploit || []} />
          </div>

          {/* Remediation Compliance */}
          <div className="grid grid-cols-2 gap-4">
            <RemediationTable title="Remediation Time Frame Compliance (Open Vulnerabilities)" data={remOpen || []} />
            <RemediationTable title="Remediation Time Frame Compliance (Closed Vulnerabilities)" data={remClosed || []} />
          </div>
        </main>
      </div>
    </div>
  );
};

// Gauge Component - EASM Risk Score style matching reference image
const GaugeChart = ({ value }: { value: number }) => {
  const cx = 200;
  const cy = 170;
  const outerRadius = 140;
  const innerRadius = 100;

  const degToRad = (d: number) => (d * Math.PI) / 180;
  const valToAngle = (v: number) => 180 - (v / 100) * 180;

  // Create thick arc segment using two arcs (outer + inner) forming a filled shape
  const arcSegment = (startVal: number, endVal: number) => {
    const a1 = degToRad(valToAngle(startVal));
    const a2 = degToRad(valToAngle(endVal));
    // Outer arc points
    const ox1 = cx + outerRadius * Math.cos(a1);
    const oy1 = cy - outerRadius * Math.sin(a1);
    const ox2 = cx + outerRadius * Math.cos(a2);
    const oy2 = cy - outerRadius * Math.sin(a2);
    // Inner arc points
    const ix1 = cx + innerRadius * Math.cos(a1);
    const iy1 = cy - innerRadius * Math.sin(a1);
    const ix2 = cx + innerRadius * Math.cos(a2);
    const iy2 = cy - innerRadius * Math.sin(a2);
    const largeArc = Math.abs(endVal - startVal) > 50 ? 1 : 0;
    return `M ${ox1} ${oy1} A ${outerRadius} ${outerRadius} 0 ${largeArc} 0 ${ox2} ${oy2} L ${ix2} ${iy2} A ${innerRadius} ${innerRadius} 0 ${largeArc} 1 ${ix1} ${iy1} Z`;
  };

  const segments = [
    { start: 0, end: 20, color: "#7dd3e8" },
    { start: 20, end: 40, color: "#4ade80" },
    { start: 40, end: 60, color: "#facc15" },
    { start: 60, end: 80, color: "#fb923c" },
    { start: 80, end: 100, color: "#ef4444" },
  ];

  const gap = 1.2;

  // Needle
  const needleAngle = degToRad(valToAngle(value));
  const needleLen = outerRadius - 8;
  const nx = cx + needleLen * Math.cos(needleAngle);
  const ny = cy - needleLen * Math.sin(needleAngle);

  return (
    <svg viewBox="0 0 400 230" className="w-80 h-48">
      {/* Arc segments - filled shapes with straight edges */}
      {segments.map((seg, i) => {
        const s = i === 0 ? seg.start : seg.start + gap / 2;
        const e = i === segments.length - 1 ? seg.end : seg.end - gap / 2;
        return (
          <path
            key={i}
            d={arcSegment(s, e)}
            fill={seg.color}
            stroke="none"
          />
        );
      })}
      {/* Tick labels */}
      {[0, 20, 40, 60, 80, 100].map((v) => {
        const a = degToRad(valToAngle(v));
        const labelR = outerRadius + 14;
        const tx = cx + labelR * Math.cos(a);
        const ty = cy - labelR * Math.sin(a);
        return (
          <text key={v} x={tx} y={ty} textAnchor="middle" dominantBaseline="central" fill="#94a3b8" fontSize={12} fontWeight={500}>
            {v}
          </text>
        );
      })}
      {/* Needle */}
      <line x1={cx} y1={cy} x2={nx} y2={ny} stroke="white" strokeWidth={2.5} strokeLinecap="round" />
      {/* Center circle */}
      <circle cx={cx} cy={cy} r={28} fill="none" stroke="#475569" strokeWidth={2} />
      <circle cx={cx} cy={cy} r={5} fill="white" />
      {/* Value below gauge */}
      <text x={cx} y={cy + 50} textAnchor="middle" dominantBaseline="central" fill="white" fontSize={32} fontWeight="bold">
        {value}
      </text>
    </svg>
  );
};

// Bar Section
const BarSection = ({ title, data }: { title: string; data: Array<{ id: string; label: string; value: number; color: string }> }) => {
  const max = Math.max(...data.map((d) => d.value), 1);
  return (
    <div className="bg-card border border-border rounded-xl p-5">
      <h3 className="text-sm font-semibold mb-4">{title}</h3>
      <div className="space-y-3">
        {data.map((d) => (
          <div key={d.id} className="flex items-center gap-3">
            <span className="text-sm w-28 shrink-0" style={{ color: d.color }}>{d.label}</span>
            <div className="flex-1 h-2.5 bg-muted rounded-full">
              <div className="h-2.5 rounded-full" style={{ width: `${(d.value / max) * 100}%`, backgroundColor: d.color }} />
            </div>
            <span className="text-sm font-medium w-8 text-right">{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

// Remediation Table
const RemediationTable = ({ title, data }: { title: string; data: Array<{ id: string; rating: string; color: string; time_frame: string; in_compliance: number; not_in_compliance: number }> }) => {
  return (
    <div className="bg-card border border-border rounded-xl p-5">
      <h3 className="text-sm font-semibold mb-4">{title}</h3>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-muted-foreground text-xs uppercase tracking-wider">
            <th className="text-left py-2">ExPRT Rating</th>
            <th className="text-left py-2">Time Frame</th>
            <th className="text-left py-2">In Compliance</th>
            <th className="text-left py-2">Not In Compliance</th>
          </tr>
        </thead>
        <tbody>
          {data.map((row) => (
            <tr key={row.id} className="border-t border-border">
              <td className="py-3 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: row.color }} />
                <span style={{ color: row.color }}>{row.rating}</span>
              </td>
              <td className="py-3 text-muted-foreground">{row.time_frame}</td>
              <td className="py-3">
                <div className="flex items-center gap-2">
                  <div className="w-20 h-2 bg-muted rounded-full">
                    <div className="h-2 rounded-full bg-green-500" style={{ width: `${row.in_compliance}%` }} />
                  </div>
                  <span className="text-green-400 text-xs">{row.in_compliance}%</span>
                </div>
              </td>
              <td className="py-3">
                <span className={`text-xs ${row.not_in_compliance > 0 ? "text-red-400" : "text-muted-foreground"}`}>
                  {row.not_in_compliance}%
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default VulnDashboard;
