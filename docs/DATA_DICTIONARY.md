# Data dictionary

CSV files use UTF-8 with BOM for Persian/Excel compatibility. Empty numeric cells mean missing, never zero.

| Field | Definition |
|---|---|
| cve_id | Registry identifier; not the publication year |
| product / group | Scoped product and descriptive category |
| published / last_modified | NVD timestamps |
| nvd_status | Saved enrichment/status label |
| cwe | Unique valid CWE-number identifiers, separated by vertical bars; blank if unavailable |
| cvss_version | 3.1 or empty |
| cvss_score / severity | Chosen 3.1 base score and threshold-derived category; Unknown if missing |
| cvss_source / cvss_vector | Source identifier and vector of selected metric |
| C / I / A | Potential confidentiality/integrity/availability impact from selected metric |
| epss / epss_date | Intentionally not collected for RQ5 |
| advisory_url | Retrieved primary disclosure supporting this row |
| validation_status | confirmed in clean data; all decision categories appear in the ledger |
| validation_method | Upstream, vendor, coordinated or researcher disclosure route |
| affected_product_evidence | Structured attribution basis |
| cpe_matches | Matching vulnerable CPEs, if present |
| nvd_url / cna_url | Independent registry links |
| advisory_snapshot / advisory_sha256 | Local response path inside the automatically expanded evidence cache, and hash of the original UTF-8 response content |
| retrieved_at | Disclosure retrieval timestamp (UTC) |
| nvd_only_score | NVD-authored CVSS 3.1 score, if available |
| description | Saved NVD English description |

Product summary: total_cves is confirmed count. high_critical uses score >=7. scored_v31 is its scored denominator. missing_v31 = total_cves - scored_v31. high_critical_pct_scored = 100 × high_critical / scored_v31 (undefined with no scores). unresolved_pairs are excluded from the primary count. upper_bound_with_unresolved = total_cves + unresolved_pairs. NVD-only columns use the narrower authored-score coverage.

Ledger categories: confirmed; excluded_unrelated (including outside scoped product variants); excluded_rejected; unresolved_advisory. Every in-window candidate pair appears exactly once.
