-- =============================================================
-- Vulnerability Dashboard: Unified KPI Views & Advanced Scoring
-- =============================================================
-- Includes: MTTR, Weaponized Risks, SLA Compliance, Risk Score,
-- Daily Trend, and Remediation Tables.
-- =============================================================

BEGIN;

-- -------------------------------------------------------------
-- 1. Safely Drop Existing Objects
-- -------------------------------------------------------------
DO $$
DECLARE
    obj_name TEXT;
BEGIN
    FOR obj_name IN
        SELECT unnest(ARRAY[
            'dash_kpi_mttr', 'dash_kpi_weaponized', 'dash_kpi_compliance',
            'dash_kpi_risk_total', 'remediation_open', 'remediation_closed',
            'vuln_daily_open', 'vuln_risk_score', 'vuln_rating_overview',
            'vuln_status_overview', 'vuln_by_status', 'vuln_by_exploit'
        ])
    LOOP
        EXECUTE format('DROP VIEW IF EXISTS public.%I CASCADE', obj_name);
        EXECUTE format('DROP TABLE IF EXISTS public.%I CASCADE', obj_name);
    END LOOP;
END $$;

-- -------------------------------------------------------------
-- 2. KPI: MTTR (Mean Time To Remediate) in Days
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.dash_kpi_mttr AS
SELECT
  'MTTR' AS label,
  COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (sr.completed_at - f.created_at)) / 86400)), 0)::int AS value,
  'Days' AS unit,
  'hsl(190 65% 58%)' AS color
FROM public.scan_findings f
JOIN public.scan_results sr ON sr.id = f.scan_id
WHERE f.status IN ('fixed', 'resolved', 'closed', 'false_positive') AND sr.completed_at IS NOT NULL;

-- -------------------------------------------------------------
-- 3. KPI: Weaponized Risks
-- -------------------------------------------------------------
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

-- -------------------------------------------------------------
-- 4. KPI: Overall SLA Compliance Percentage
-- -------------------------------------------------------------
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
      WHEN UPPER(sev) = 'MEDIUM'   THEN interval '90 days'
      ELSE interval '180 days'
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

-- -------------------------------------------------------------
-- 5. Chart: Open Vulnerabilities by Day (Last 45 Days)
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.vuln_daily_open AS
WITH RECURSIVE days AS (
  SELECT (CURRENT_DATE - INTERVAL '44 days')::DATE AS day_date, 1 AS day_num
  UNION ALL
  SELECT (day_date + INTERVAL '1 day')::DATE, day_num + 1
  FROM days
  WHERE day_num < 45
)
SELECT
  md5(d.day_date::text)::uuid AS id,
  d.day_num AS day,
  COUNT(f.id)::int AS count
FROM days d
LEFT JOIN public.scan_findings f ON f.created_at::date <= d.day_date
  AND (f.status = 'open' OR (f.status IN ('fixed', 'resolved', 'closed', 'false_positive') AND EXISTS (
      SELECT 1 FROM public.scan_results sr WHERE sr.id = f.scan_id AND (sr.completed_at::date > d.day_date OR sr.completed_at IS NULL)
  )))
GROUP BY d.day_date, d.day_num
ORDER BY d.day_num;

-- -------------------------------------------------------------
-- 6. Chart: Risk Score Breakdown (CVSS * Exploit * Asset * Exp)
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.vuln_risk_score AS
WITH finding_risk AS (
  SELECT
    f.id,
    -- 1. Base Score (CVSS)
    (
      SELECT COALESCE(MAX(c.cvss_v3_score), 5.0)
      FROM public.finding_cves fc
      JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
      WHERE fc.finding_id = f.id
    ) AS base_score,
    -- 2. Exploit Factor
    CASE
      WHEN EXISTS (SELECT 1 FROM public.finding_cves fc JOIN public.exploits e ON e.cve_id = fc.cve_id WHERE fc.finding_id = f.id AND e.verified IS TRUE) THEN 1.8
      WHEN EXISTS (SELECT 1 FROM public.finding_cves fc JOIN public.exploits e ON e.cve_id = fc.cve_id WHERE fc.finding_id = f.id) THEN 1.4
      ELSE 1.0
    END AS exploit_factor,
    -- 3. Asset Criticality (Inferred from service)
    CASE
      WHEN f.service ~* '(postgres|mysql|sql|oracle|db|mongodb|redis)' THEN 1.6
      WHEN f.service ~* '(auth|ldap|ad|kerberos|pax)' THEN 1.8
      ELSE 1.0
    END AS criticality_factor,
    -- 4. Exposure Factor
    CASE
      WHEN f.service ~* '(http|https|ssh|rdp|vnc|ftp|smtp)' THEN 1.3
      ELSE 1.0
    END AS exposure_factor
  FROM public.scan_findings f
  WHERE f.status = 'open'
),
cumulative_scores AS (
  SELECT
    base_score,
    (base_score * exploit_factor) - base_score AS exploit_impact,
    (base_score * exploit_factor * criticality_factor) - (base_score * exploit_factor) AS asset_impact,
    (base_score * exploit_factor * criticality_factor * exposure_factor) - (base_score * exploit_factor * criticality_factor) AS exposure_impact
  FROM finding_risk
)
SELECT
  md5(label)::uuid AS id,
  label,
  COALESCE(ROUND(SUM(val)), 0)::int AS value,
  color,
  sort_order
FROM (
  SELECT 'Base CVSS' AS label, SUM(base_score) AS val, 'hsl(210 70% 55%)' AS color, 1 AS sort_order FROM cumulative_scores
  UNION ALL
  SELECT 'Exploitability' AS label, SUM(exploit_impact) AS val, 'hsl(0 72% 55%)' AS color, 2 AS sort_order FROM cumulative_scores
  UNION ALL
  SELECT 'Asset Criticality' AS label, SUM(asset_impact) AS val, 'hsl(270 60% 55%)' AS color, 3 AS sort_order FROM cumulative_scores
  UNION ALL
  SELECT 'Exposure' AS label, SUM(exposure_impact) AS val, 'hsl(30 90% 55%)' AS color, 4 AS sort_order FROM cumulative_scores
) sub
GROUP BY label, color, sort_order
ORDER BY sort_order;

-- -------------------------------------------------------------
-- 6b. KPI: Total Risk Score (Single value)
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.dash_kpi_risk_total AS
SELECT
  'Total Risk' AS label,
  COALESCE(SUM(value), 0)::int AS value,
  'Score' AS unit,
  'hsl(45 75% 62%)' AS color
FROM public.vuln_risk_score;

-- -------------------------------------------------------------
-- 7. View: Vulnerability Rating Overview (CVSS)
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.vuln_rating_overview AS
WITH total AS (SELECT COUNT(*)::float as cnt FROM public.scan_findings WHERE status = 'open'),
counts AS (
  SELECT
    CASE
      WHEN UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'CRITICAL' THEN 'Critical'
      WHEN UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'HIGH' THEN 'High'
      WHEN UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'MEDIUM' THEN 'Medium'
      ELSE 'Low'
    END AS rating,
    COUNT(f.id) as val
  FROM public.scan_findings f
  LEFT JOIN public.finding_cves fc ON fc.finding_id = f.id
  LEFT JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
  WHERE f.status = 'open'
  GROUP BY 1
)
SELECT
  md5(r.label)::uuid as id,
  r.label,
  COALESCE(c.val, 0)::int as value,
  CASE
    WHEN (SELECT cnt FROM total) = 0 THEN 0
    ELSE ROUND((COALESCE(c.val, 0)::float / (SELECT cnt FROM total)) * 100)::int
  END as percentage,
  r.color,
  r.sort_order
FROM (
  VALUES
    ('Critical', 'hsl(0 72% 55%)', 1),
    ('High', 'hsl(25 95% 55%)', 2),
    ('Medium', 'hsl(210 70% 55%)', 3),
    ('Low', 'hsl(150 70% 50%)', 4)
) r(label, color, sort_order)
LEFT JOIN counts c ON c.rating = r.label
ORDER BY sort_order;

-- -------------------------------------------------------------
-- 8. View: Vulnerability Status Overview
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.vuln_status_overview AS
WITH total AS (SELECT COUNT(*)::float as cnt FROM public.scan_findings),
counts AS (
  SELECT
    CASE
      WHEN status = 'open' THEN 'Open'
      WHEN status = 'triaged' THEN 'In Progress'
      WHEN status IN ('fixed', 'resolved', 'closed') THEN 'Closed'
      WHEN status = 'false_positive' THEN 'Suppressed'
      ELSE 'Open'
    END AS stat,
    COUNT(id) as val
  FROM public.scan_findings
  GROUP BY 1
)
SELECT
  md5(r.label)::uuid as id,
  r.label,
  COALESCE(c.val, 0)::int as value,
  CASE
    WHEN (SELECT cnt FROM total) = 0 THEN 0
    ELSE ROUND((COALESCE(c.val, 0)::float / (SELECT cnt FROM total)) * 100)::int
  END as percentage,
  r.color,
  r.sort_order
FROM (
  VALUES
    ('Open', 'hsl(0 72% 55%)', 1),
    ('In Progress', 'hsl(30 90% 55%)', 2),
    ('Closed', 'hsl(150 70% 50%)', 3),
    ('Suppressed', 'hsl(210 15% 55%)', 4)
) r(label, color, sort_order)
LEFT JOIN counts c ON c.stat = r.label
ORDER BY sort_order;

-- -------------------------------------------------------------
-- 9. Bar Chart: By Status
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.vuln_by_status AS
SELECT
  md5(label)::uuid as id,
  label,
  value,
  color,
  sort_order
FROM public.vuln_status_overview;

-- -------------------------------------------------------------
-- 10. Bar Chart: By Exploit Status
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.vuln_by_exploit AS
WITH counts AS (
  SELECT
    CASE
      WHEN EXISTS (SELECT 1 FROM public.finding_cves fc JOIN public.exploits e ON e.cve_id = fc.cve_id WHERE fc.finding_id = f.id AND e.verified IS TRUE) THEN 'Actively Used'
      WHEN EXISTS (SELECT 1 FROM public.finding_cves fc JOIN public.exploits e ON e.cve_id = fc.cve_id WHERE fc.finding_id = f.id) THEN 'Available'
      ELSE 'None'
    END AS expl_stat,
    COUNT(f.id) as val
  FROM public.scan_findings f
  WHERE f.status = 'open'
  GROUP BY 1
)
SELECT
  md5(r.label)::uuid as id,
  r.label,
  COALESCE(c.val, 0)::int as value,
  r.color,
  r.sort_order
FROM (
  VALUES
    ('Actively Used', 'hsl(0 72% 55%)', 1),
    ('Available', 'hsl(30 90% 55%)', 2),
    ('None', 'hsl(210 15% 55%)', 3)
) r(label, color, sort_order)
LEFT JOIN counts c ON c.expl_stat = r.label
ORDER BY sort_order;

-- -------------------------------------------------------------
-- 11. Remediation Table (Open)
-- -------------------------------------------------------------
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

-- -------------------------------------------------------------
-- 12. Remediation Table (Closed)
-- -------------------------------------------------------------
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

-- -------------------------------------------------------------
-- 13. Grants
-- -------------------------------------------------------------
GRANT SELECT ON
  public.dash_kpi_mttr,
  public.dash_kpi_weaponized,
  public.dash_kpi_compliance,
  public.dash_kpi_risk_total,
  public.remediation_open,
  public.remediation_closed,
  public.vuln_daily_open,
  public.vuln_risk_score,
  public.vuln_rating_overview,
  public.vuln_status_overview,
  public.vuln_by_status,
  public.vuln_by_exploit
TO anon, authenticated;

COMMIT;
