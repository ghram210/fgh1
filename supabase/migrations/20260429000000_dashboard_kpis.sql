-- =============================================================
-- Dashboard KPI Views: MTTR, Weaponized Risks, SLA Compliance
-- =============================================================

BEGIN;

-- 1. MTTR (Mean Time To Remediate) in Days
-- Proxy: Average days between discovery and last update for non-open findings
-- Since we don't have a strict resolution_date, we use the scan completion time
-- of the scan that reported the finding.
CREATE OR REPLACE VIEW public.dash_kpi_mttr AS
SELECT
  'MTTR' AS label,
  COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (sr.completed_at - f.created_at)) / 86400)), 0)::int AS value,
  'Days' AS unit,
  'hsl(190 65% 58%)' AS color
FROM public.scan_findings f
JOIN public.scan_results sr ON sr.id = f.scan_id
WHERE f.status IN ('fixed', 'resolved', 'closed') AND sr.completed_at IS NOT NULL;

-- 2. Weaponized Risks
-- Count of unique open scan findings that are linked to a CVE with a verified exploit
CREATE OR REPLACE VIEW public.dash_kpi_weaponized AS
SELECT
  'Weaponized' AS label,
  COUNT(DISTINCT f.id)::int AS value,
  'Risks' AS unit,
  'hsl(355 70% 62%)' AS color
FROM public.scan_findings f
WHERE f.status = 'open'
  AND EXISTS (
    SELECT 1 FROM public.finding_cves fc
    JOIN public.exploits e ON e.cve_id = fc.cve_id
    WHERE fc.finding_id = f.id AND e.verified IS TRUE
  );

-- 3. Overall SLA Compliance Percentage
-- % of open findings that are within the allowed timeframe
-- Critical: 7 days, High: 30 days, others: 90 days
CREATE OR REPLACE VIEW public.dash_kpi_compliance AS
WITH findings_with_deadline AS (
  SELECT
    f.id,
    f.created_at,
    (
      SELECT COALESCE(c.cvss_v3_severity, 'MEDIUM')
      FROM public.finding_cves fc
      JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
      WHERE fc.finding_id = f.id
      LIMIT 1
    ) AS sev
  FROM public.scan_findings f
  WHERE f.status = 'open'
),
deadlines AS (
  SELECT
    id,
    created_at,
    CASE
      WHEN UPPER(sev) = 'CRITICAL' THEN interval '7 days'
      WHEN UPPER(sev) = 'HIGH'     THEN interval '30 days'
      ELSE interval '90 days'
    END AS allowed_time
  FROM findings_with_deadline
),
compliance_stats AS (
  SELECT
    COUNT(*) AS total_open,
    COUNT(*) FILTER (WHERE (now() - created_at) <= allowed_time) AS in_compliance
  FROM deadlines
)
SELECT
  'Compliance' AS label,
  CASE
    WHEN total_open = 0 THEN 100
    ELSE ROUND((in_compliance::float / total_open::float) * 100)::int
  END AS value,
  '%' AS unit,
  'hsl(155 50% 55%)' AS color
FROM compliance_stats;

-- 4. Active Risk Score
-- Sum of CVSS scores for all open findings (proxy for total liability)
CREATE OR REPLACE VIEW public.dash_kpi_risk_total AS
WITH finding_scores AS (
  SELECT
    f.id,
    (
      SELECT MAX(COALESCE(c.cvss_v3_score, 5.0))
      FROM public.finding_cves fc
      JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
      WHERE fc.finding_id = f.id
    ) AS score
  FROM public.scan_findings f
  WHERE f.status = 'open'
)
SELECT
  'Total Risk' AS label,
  COALESCE(ROUND(SUM(COALESCE(score, 5.0))), 0)::int AS value,
  'Score' AS unit,
  'hsl(45 75% 62%)' AS color
FROM finding_scores;

GRANT SELECT ON
  public.dash_kpi_mttr,
  public.dash_kpi_weaponized,
  public.dash_kpi_compliance,
  public.dash_kpi_risk_total
TO anon, authenticated;

COMMIT;
