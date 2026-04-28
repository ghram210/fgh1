-- =============================================================
-- Dashboard KPI Views: MTTR, Weaponized Risks, SLA Compliance,
-- and dynamic Remediation Compliance Tables.
-- =============================================================

BEGIN;

-- 1. Drop existing objects if they exist as tables (from early mocks)
DROP TABLE IF EXISTS public.remediation_open CASCADE;
DROP TABLE IF EXISTS public.remediation_closed CASCADE;

-- 2. MTTR (Mean Time To Remediate) in Days
CREATE OR REPLACE VIEW public.dash_kpi_mttr AS
SELECT
  'MTTR' AS label,
  COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (sr.completed_at - f.created_at)) / 86400)), 0)::int AS value,
  'Days' AS unit,
  'hsl(190 65% 58%)' AS color
FROM public.scan_findings f
JOIN public.scan_results sr ON sr.id = f.scan_id
WHERE f.status IN ('fixed', 'resolved', 'closed') AND sr.completed_at IS NOT NULL;

-- 3. Weaponized Risks
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

-- 4. Overall SLA Compliance Percentage
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
    CASE
      WHEN UPPER(sev) = 'CRITICAL' THEN interval '7 days'
      WHEN UPPER(sev) = 'HIGH'     THEN interval '30 days'
      ELSE interval '90 days'
    END AS allowed_time,
    created_at
  FROM findings_with_deadline
),
stats AS (
  SELECT
    COUNT(*) AS total_open,
    COUNT(*) FILTER (WHERE (now() - created_at) <= allowed_time) AS in_comp
  FROM deadlines
)
SELECT
  'Compliance' AS label,
  CASE WHEN total_open = 0 THEN 100 ELSE ROUND((in_comp::float / total_open::float) * 100)::int END AS value,
  '%' AS unit,
  'hsl(155 50% 55%)' AS color
FROM stats;

-- 5. Active Risk Score
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
  COALESCE(ROUND(SUM(score)), 0)::int AS value,
  'Score' AS unit,
  'hsl(45 75% 62%)' AS color
FROM finding_scores;

-- 6. Dynamic Remediation Table (Open Vulnerabilities)
CREATE OR REPLACE VIEW public.remediation_open AS
WITH sev_levels(rating, color, sort_order, allowed_days) AS (
  VALUES
    ('Critical', 'hsl(355 70% 62%)', 1, 7),
    ('High',     'hsl(25 78% 62%)',  2, 30),
    ('Medium',   'hsl(45 75% 62%)',  3, 90),
    ('Low',      'hsl(155 50% 55%)', 4, 180)
),
findings_stats AS (
  SELECT
    sl.rating,
    COUNT(f.id) AS total_count,
    COUNT(f.id) FILTER (WHERE (now() - f.created_at) <= (sl.allowed_days * interval '1 day')) AS in_comp_count
  FROM sev_levels sl
  LEFT JOIN (
    SELECT f.id, f.created_at, COALESCE(c.cvss_v3_severity, 'MEDIUM') AS sev
    FROM public.scan_findings f
    LEFT JOIN public.finding_cves fc ON fc.finding_id = f.id
    LEFT JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
    WHERE f.status = 'open'
  ) f ON UPPER(f.sev) = UPPER(sl.rating)
  GROUP BY sl.rating
)
SELECT
  md5(sl.rating)::uuid AS id,
  sl.rating,
  sl.color,
  'last_30_days' AS time_frame,
  CASE WHEN fs.total_count = 0 THEN 100 ELSE ROUND((fs.in_comp_count::float / fs.total_count::float) * 100)::int END AS in_compliance,
  CASE WHEN fs.total_count = 0 THEN 0   ELSE 100 - ROUND((fs.in_comp_count::float / fs.total_count::float) * 100)::int END AS not_in_compliance,
  sl.sort_order
FROM sev_levels sl
LEFT JOIN findings_stats fs ON fs.rating = sl.rating;

-- 7. Dynamic Remediation Table (Closed Vulnerabilities)
CREATE OR REPLACE VIEW public.remediation_closed AS
WITH sev_levels(rating, color, sort_order, allowed_days) AS (
  VALUES
    ('Critical', 'hsl(155 50% 55%)', 1, 7),
    ('High',     'hsl(155 50% 55%)', 2, 30),
    ('Medium',   'hsl(155 50% 55%)', 3, 90),
    ('Low',      'hsl(155 50% 55%)', 4, 180)
),
findings_stats AS (
  SELECT
    sl.rating,
    COUNT(f.id) AS total_count,
    COUNT(f.id) FILTER (WHERE (sr.completed_at - f.created_at) <= (sl.allowed_days * interval '1 day')) AS in_comp_count
  FROM sev_levels sl
  LEFT JOIN (
    SELECT f.id, f.created_at, f.scan_id, COALESCE(c.cvss_v3_severity, 'MEDIUM') AS sev
    FROM public.scan_findings f
    LEFT JOIN public.finding_cves fc ON fc.finding_id = f.id
    LEFT JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
    WHERE f.status IN ('fixed', 'resolved', 'closed')
  ) f ON UPPER(f.sev) = UPPER(sl.rating)
  LEFT JOIN public.scan_results sr ON sr.id = f.scan_id
  GROUP BY sl.rating
)
SELECT
  md5(sl.rating || 'closed')::uuid AS id,
  sl.rating,
  sl.color,
  'last_30_days' AS time_frame,
  CASE WHEN fs.total_count = 0 THEN 100 ELSE ROUND((fs.in_comp_count::float / fs.total_count::float) * 100)::int END AS in_compliance,
  CASE WHEN fs.total_count = 0 THEN 0   ELSE 100 - ROUND((fs.in_comp_count::float / fs.total_count::float) * 100)::int END AS not_in_compliance,
  sl.sort_order
FROM sev_levels sl
LEFT JOIN findings_stats fs ON fs.rating = sl.rating;

GRANT SELECT ON
  public.dash_kpi_mttr,
  public.dash_kpi_weaponized,
  public.dash_kpi_compliance,
  public.dash_kpi_risk_total,
  public.remediation_open,
  public.remediation_closed
TO anon, authenticated;

COMMIT;
