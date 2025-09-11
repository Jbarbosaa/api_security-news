NIST/NVD Vulnerability Fetcher — README

A lightweight Python tool that queries the NIST NVD API using specific keywords/CPEs, filters results (date windows, severity, products/assets), and exports clean CSVs ready for dashboards and visual/strategic analysis of vulnerabilities per asset, by date and criticality.

✨ What it does

Queries NVD (National Vulnerability Database) API with:

Free-text keywords (e.g., "openssl", "windows server 2022")

Optional CPE filters to target specific vendors/products

Optional date windows (published/last-modified)

Normalizes and filters CVE data:

CVSS v3.1 score & severity

CWE (weakness), affected vendor/product/version

Published & last-modified dates

Outputs flat, analysis-friendly CSVs for BI tools and Python notebooks.

🧭 Typical workflow

Define your keywords (and/or CPEs) that represent the assets you manage.

Run the script to fetch + filter vulnerabilities.

Load the exported CSV into Pandas / Power BI / Grafana / Metabase.

Track trends by date, asset, and severity to prioritize remediation.
