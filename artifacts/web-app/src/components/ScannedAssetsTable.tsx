import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Monitor } from "lucide-react";

const riskStyles: Record<
  string,
  { dot: string; text: string; bg: string; border: string }
> = {
  Critical: {
    dot: "bg-severity-critical",
    text: "text-severity-critical",
    bg: "bg-severity-critical/15",
    border: "border-severity-critical/40",
  },
  High: {
    dot: "bg-severity-high",
    text: "text-severity-high",
    bg: "bg-severity-high/15",
    border: "border-severity-high/40",
  },
  Medium: {
    dot: "bg-severity-medium",
    text: "text-severity-medium",
    bg: "bg-severity-medium/15",
    border: "border-severity-medium/40",
  },
  Low: {
    dot: "bg-severity-low",
    text: "text-severity-low",
    bg: "bg-severity-low/15",
    border: "border-severity-low/40",
  },
  Info: {
    dot: "bg-severity-info",
    text: "text-severity-info",
    bg: "bg-severity-info/15",
    border: "border-severity-info/40",
  },
  None: {
    dot: "bg-severity-none",
    text: "text-severity-none",
    bg: "bg-severity-none/15",
    border: "border-severity-none/40",
  },
};

const formatDate = (raw: unknown): string => {
  if (!raw) return "—";
  const d = new Date(String(raw));
  if (Number.isNaN(d.getTime())) return String(raw);
  return d.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
};

const headerCellClass =
  "text-left px-4 py-3.5 text-[13px] font-bold text-primary uppercase tracking-wider";
const bodyCellClass = "px-4 py-4 align-middle";

const ScannedAssetsTable = () => {
  const { data: assets = [], isLoading } = useQuery({
    queryKey: ["scanned_assets"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("scanned_assets")
        .select("*")
        .order("last_scan", { ascending: false });
      if (error) throw error;
      return data ?? [];
    },
  });

  return (
    <div className="bg-card rounded-xl border border-border/80 overflow-hidden">
      <div className="flex items-center justify-between px-5 py-4 border-b border-border/60">
        <div className="flex items-center gap-2">
          <Monitor className="w-4 h-4 text-primary" />
          <h3 className="text-[15px] font-semibold text-foreground tracking-tight">
            Scanned Assets
          </h3>
          {!isLoading && (
            <span className="text-[11px] text-muted-foreground ml-1">
              ({assets.length.toLocaleString("en-US")})
            </span>
          )}
        </div>
        <button className="text-xs text-primary hover:text-primary/80 transition-colors font-medium">
          All assets
        </button>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full table-fixed">
          <colgroup>
            <col style={{ width: "16%" }} />
            <col style={{ width: "17%" }} />
            <col style={{ width: "17%" }} />
            <col style={{ width: "18%" }} />
            <col style={{ width: "14%" }} />
            <col style={{ width: "18%" }} />
          </colgroup>
          <thead>
            <tr className="bg-secondary/30">
              <th className={headerCellClass}>IP</th>
              <th className={headerCellClass}>Hostname</th>
              <th className={headerCellClass}>OS</th>
              <th className={headerCellClass}>Open Ports</th>
              <th className={headerCellClass}>Risk</th>
              <th className={headerCellClass}>Last Scan</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr>
                <td
                  colSpan={6}
                  className="px-5 py-8 text-center text-sm text-muted-foreground"
                >
                  Loading assets…
                </td>
              </tr>
            )}
            {!isLoading && assets.length === 0 && (
              <tr>
                <td
                  colSpan={6}
                  className="px-5 py-8 text-center text-sm text-muted-foreground"
                >
                  No scanned assets yet — run your first scan from the
                  Vulnerabilities tab.
                </td>
              </tr>
            )}
            {assets.map((a) => {
              const risk = (a.risk as string) ?? "Info";
              const styles = riskStyles[risk] ?? riskStyles.Info;
              return (
                <tr
                  key={a.id}
                  className="border-t border-border/50 hover:bg-secondary/40 transition-colors"
                >
                  <td className={`${bodyCellClass} text-primary font-mono text-[15px] font-semibold truncate`}>
                    {a.ip_address ?? "—"}
                  </td>
                  <td className={`${bodyCellClass} text-foreground text-[15px] truncate`}>
                    {a.hostname ?? "—"}
                  </td>
                  <td className={`${bodyCellClass} text-foreground/85 text-[15px] truncate`}>
                    {a.os ?? "—"}
                  </td>
                  <td className={`${bodyCellClass} text-foreground/85 font-mono text-[15px] truncate`}>
                    {a.open_ports ?? "—"}
                  </td>
                  <td className={bodyCellClass}>
                    <span
                      className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-md text-[14px] font-bold border ${styles.bg} ${styles.text} ${styles.border}`}
                    >
                      <span className={`w-2.5 h-2.5 rounded-full ${styles.dot}`} />
                      {risk}
                    </span>
                  </td>
                  <td className={`${bodyCellClass} text-foreground/75 text-[14.5px] tabular-nums truncate`}>
                    {formatDate(a.last_scan)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ScannedAssetsTable;
