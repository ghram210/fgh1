import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import { AlertTriangle, MoreHorizontal } from "lucide-react";
import { cn } from "@/lib/utils";

const filterTags = [
  "Open vulnerabilities",
  "Adversaries",
  "Asset confidence",
  "Asset criticality",
  "Asset roles",
  "CISA KEV",
  "CISA KEV due date compliant",
  "Cloud provider",
  "CVSS complexity",
];

type SeverityKey = "Critical" | "High" | "Medium" | "Low" | "Info" | "None";

const severityStyles: Record<SeverityKey, { dot: string; text: string; hex: string }> = {
  Critical: { dot: "bg-severity-critical", text: "text-severity-critical", hex: "hsl(0 84% 60%)" },
  High: { dot: "bg-severity-high", text: "text-severity-high", hex: "hsl(24 95% 53%)" },
  Medium: { dot: "bg-severity-medium", text: "text-severity-medium", hex: "hsl(45 93% 47%)" },
  Low: { dot: "bg-severity-low", text: "text-severity-low", hex: "hsl(142 71% 45%)" },
  Info: { dot: "bg-severity-info", text: "text-severity-info", hex: "hsl(215 20% 65%)" },
  None: { dot: "bg-severity-none", text: "text-severity-none", hex: "hsl(215 15% 75%)" },
};

const fallbackStyle = { dot: "bg-muted-foreground", text: "text-muted-foreground" };

const exploitStyles: Record<string, { dot: string; text: string; bg: string }> = {
  "Actively used": {
    dot: "bg-severity-critical",
    text: "text-severity-critical",
    bg: "bg-severity-critical/15",
  },
  Available: {
    dot: "bg-severity-high",
    text: "text-severity-high",
    bg: "bg-severity-high/15",
  },
  Unproven: {
    dot: "bg-severity-medium",
    text: "text-severity-medium",
    bg: "bg-severity-medium/15",
  },
  None: {
    dot: "bg-severity-none",
    text: "text-severity-none",
    bg: "bg-severity-none/15",
  },
};

const SeverityCell = ({ value }: { value: string | null | undefined }) => {
  if (!value) return <span className="text-muted-foreground">—</span>;
  const style = severityStyles[value as SeverityKey] ?? fallbackStyle;
  const color = "hex" in style ? style.hex : undefined;
  return (
    <span className="inline-flex items-center gap-2">
      <span className={`w-2.5 h-2.5 rounded-full ${style.dot}`} style={color ? { backgroundColor: color } : {}} />
      <span className={`font-medium ${style.text}`} style={color ? { color } : {}}>{value}</span>
    </span>
  );
};

const ExploitCell = ({ value }: { value: string | null | undefined }) => {
  const v = value ?? "None";
  const style =
    exploitStyles[v] ??
    {
      dot: "bg-muted-foreground",
      text: "text-foreground",
      bg: "bg-secondary",
    };
  return (
    <span
      className={`inline-flex items-center gap-2 px-2.5 py-1 rounded-md text-xs font-semibold ${style.bg} ${style.text}`}
    >
      <span className={`w-2 h-2 rounded-full ${style.dot}`} />
      {v}
    </span>
  );
};

const VulnerabilitiesTab = () => {
  const navigate = useNavigate();
  const [filterRating, setFilterRating] = useState("all");
  const [filterExploit, setFilterExploit] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [showRatingDrop, setShowRatingDrop] = useState(false);
  const [showExploitDrop, setShowExploitDrop] = useState(false);
  const [showStatusDrop, setShowStatusDrop] = useState(false);

  const { data: vulnerabilities = [] } = useQuery({
    queryKey: ["vulnerabilities"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("vulnerabilities")
        .select("*")
        .order("created_at", { ascending: true });
      if (error) throw error;
      return data;
    },
  });

  // Pull CVSS scores + published dates from cve_catalog so we can show
  // a real numeric column instead of REMEDIATIONS.
  const cveIds = useMemo(
    () =>
      Array.from(
        new Set(
          vulnerabilities
            .map((v) => v.cve_id)
            .filter((x): x is string => Boolean(x))
        )
      ),
    [vulnerabilities]
  );

  const { data: cveCatalog = [] } = useQuery({
    queryKey: ["cve_catalog_for_vulns", cveIds.length, cveIds.join(",")],
    enabled: cveIds.length > 0,
    queryFn: async () => {
      const { data, error } = await supabase
        .from("cve_catalog")
        .select("cve_id, cvss_v3_score, published_date")
        .in("cve_id", cveIds);
      if (error) throw error;
      return data ?? [];
    },
  });

  const cveMap = useMemo(() => {
    const m = new Map<string, { score: number | null; published: string | null }>();
    for (const c of cveCatalog) {
      m.set(c.cve_id, {
        score: c.cvss_v3_score ?? null,
        published: c.published_date ?? null,
      });
    }
    return m;
  }, [cveCatalog]);

  const filtered = vulnerabilities.filter((v) => {
    if (filterRating !== "all" && v.cvss_severity !== filterRating) return false;
    if (filterExploit !== "all" && v.exploit_status !== filterExploit) return false;
    if (filterStatus !== "all" && v.status !== filterStatus) return false;
    return true;
  });

  const ratingOptions = ["All Ratings", "Critical", "High", "Medium", "Low"];
  const exploitOptions = ["All Exploits", "Actively Used", "Available", "Unproven", "None"];
  const statusOptions = ["All Status", "Open", "In Progress", "Closed", "Suppressed"];

  const closeAllDrops = () => {
    setShowRatingDrop(false);
    setShowExploitDrop(false);
    setShowStatusDrop(false);
  };

  const DropdownFilter = ({
    label,
    value,
    options,
    show,
    setShow,
    setValue,
  }: {
    label: string;
    value: string;
    options: string[];
    show: boolean;
    setShow: (v: boolean) => void;
    setValue: (v: string) => void;
  }) => {
    const allLabel = options[0];
    return (
      <div className="relative">
        <button
          onClick={() => {
            closeAllDrops();
            setShow(!show);
          }}
          className="flex items-center gap-2 px-3 py-1.5 text-sm bg-secondary border border-border rounded-lg"
        >
          {value === "all" ? allLabel : value}
          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </button>
        {show && (
          <div className="absolute z-10 mt-1 bg-card border border-border rounded-lg shadow-lg py-1 min-w-[160px]">
            {options.map((opt) => {
              const val = opt === allLabel ? "all" : opt;
              const active = value === val;
              return (
                <button
                  key={opt}
                  onClick={() => {
                    setValue(val);
                    setShow(false);
                  }}
                  className={cn(
                    "w-full text-left px-3 py-1.5 text-sm hover:bg-accent",
                    active ? "bg-primary text-primary-foreground" : ""
                  )}
                >
                  {opt} {active && "✓"}
                </button>
              );
            })}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-4">
      {/* Filter row */}
      <div className="flex items-center gap-4">
        <span className="text-sm text-muted-foreground">Filter by:</span>
        <DropdownFilter
          label="Ratings"
          value={filterRating}
          options={ratingOptions}
          show={showRatingDrop}
          setShow={setShowRatingDrop}
          setValue={setFilterRating}
        />
        <DropdownFilter
          label="Exploits"
          value={filterExploit}
          options={exploitOptions}
          show={showExploitDrop}
          setShow={setShowExploitDrop}
          setValue={setFilterExploit}
        />
        <DropdownFilter
          label="Status"
          value={filterStatus}
          options={statusOptions}
          show={showStatusDrop}
          setShow={setShowStatusDrop}
          setValue={setFilterStatus}
        />
        <span className="ml-auto text-sm text-muted-foreground">{filtered.length.toLocaleString("en-US")} results</span>
      </div>

      {/* Info banner */}
      <div className="bg-card rounded-lg border border-border p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-severity-high" />
            <span className="text-sm font-medium text-foreground">
              {filtered.length.toLocaleString("en-US")} vulnerabilities found on {filtered.length.toLocaleString("en-US")} vulnerability IDs
            </span>
          </div>
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            <span className="flex items-center gap-1">⊕ Grouped by Vulnerability ID</span>
            <span>Create scheduled report</span>
            <span>↓ Export</span>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 mb-2">
          {filterTags.map((tag, i) => (
            <span key={i} className="text-xs px-2 py-1 rounded text-muted-foreground">
              {tag}
              {i === 2 && (
                <span className="ml-1 px-1.5 py-0.5 rounded-full bg-severity-high/20 text-severity-high text-xs">
                  1 excluded
                </span>
              )}
            </span>
          ))}
          <span className="text-xs text-primary cursor-pointer">Add/remove filters</span>
        </div>
        <div className="text-right">
          <span className="text-xs text-muted-foreground cursor-pointer hover:text-foreground">Clear all</span>
        </div>
      </div>

      {/* Table */}
      <div className="bg-card rounded-lg border border-border overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-secondary/30">
              <th className="text-left px-5 py-3 text-xs font-bold text-primary uppercase tracking-wider">CVE</th>
              <th className="text-left px-5 py-3 text-xs font-bold text-primary uppercase tracking-wider">Exprt Rating</th>
              <th className="text-left px-5 py-3 text-xs font-bold text-primary uppercase tracking-wider">CVSS Severity</th>
              <th className="text-left px-5 py-3 text-xs font-bold text-primary uppercase tracking-wider">Description</th>
              <th className="text-left px-5 py-3 text-xs font-bold text-primary uppercase tracking-wider">Affected</th>
              <th className="text-left px-5 py-3 text-xs font-bold text-primary uppercase tracking-wider">Exploit Status</th>
              <th className="text-left px-5 py-3 text-xs font-bold text-primary uppercase tracking-wider">CVSS Score</th>
              <th className="text-left px-5 py-3 text-xs font-bold text-primary uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((v) => {
              const sev = (v.cvss_severity as SeverityKey) ?? "Info";
              const sevStyle = severityStyles[sev] ?? fallbackStyle;
              const dot = sevStyle.dot;
              const color = "hex" in sevStyle ? sevStyle.hex : undefined;
              const cveInfo = cveMap.get(v.cve_id);
              const score = cveInfo?.score;
              const scoreStyle = severityStyles[sev] ?? fallbackStyle;
              return (
                <tr
                  key={v.id}
                  className="border-t border-border hover:bg-secondary/50 transition-colors cursor-pointer"
                  onClick={() => navigate("/scan-results")}
                >
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-2">
                      <span className={`w-2.5 h-2.5 rounded-full ${dot}`} style={color ? { backgroundColor: color } : {}} />
                      <span className="text-primary font-mono text-xs font-semibold">
                        {v.cve_id ?? "—"}
                      </span>
                    </div>
                  </td>
                  <td className="px-5 py-3.5">
                    <SeverityCell value={v.exprt_rating} />
                  </td>
                  <td className="px-5 py-3.5">
                    <SeverityCell value={v.cvss_severity} />
                  </td>
                  <td className="px-5 py-3.5 text-foreground/85 max-w-[320px]">
                    <span className="line-clamp-2 leading-snug" title={v.description ?? ""}>
                      {v.description ?? "—"}
                    </span>
                  </td>
                  <td className="px-5 py-3.5 text-foreground text-center font-medium tabular-nums">
                    {(v.vulnerability_count ?? 0).toLocaleString("en-US")}
                  </td>
                  <td className="px-5 py-3.5">
                    <ExploitCell value={v.exploit_status} />
                  </td>
                  <td className="px-5 py-3.5">
                    {score !== undefined && score !== null ? (
                      <span
                        className={`inline-flex items-center justify-center min-w-[44px] px-2 py-1 rounded-md text-xs font-bold tabular-nums bg-secondary border border-border ${scoreStyle.text}`}
                        style={color ? { color } : {}}
                      >
                        {Number(score).toLocaleString("en-US", { minimumFractionDigits: 1, maximumFractionDigits: 1 })}
                      </span>
                    ) : (
                      <span className="text-muted-foreground text-xs">—</span>
                    )}
                  </td>
                  <td className="px-5 py-3.5">
                    <button
                      className="text-muted-foreground hover:text-foreground"
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate("/scan-results");
                      }}
                    >
                      <MoreHorizontal className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              );
            })}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={8} className="px-5 py-8 text-center text-sm text-muted-foreground">
                  No vulnerabilities match the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default VulnerabilitiesTab;
