# Study protocol and limitations

## Question and scope

RQ5 asks which selected products have the most reported CVEs and the most High/Critical cases. The purposive set is the seven core products listed in the assignment. Optional LlamaIndex, CrewAI and AutoGen are excluded to keep a manageable fixed set, not because of their observed counts. Configuration documents each vendor, repository, alias and product boundary. LangChain includes its official Python/JavaScript libraries; LangGraph, LangSmith, Helm and third-party forks are excluded. Langflow covers OSS server packages, not Desktop. Flowise includes server/components/chat embed. The groups are descriptive metadata, not a separate RQ3 hypothesis test.

Window: NVD published >= 2023-01-01 and < 2026-11-01 (UTC). Snapshot: 2026-11-11. We follow the brief's October cutoff to avoid an incomplete November; this is not an annual trend analysis. Historical CVE IDs can have later publication dates. Metrics reflect collection-time records, not a reconstruction as of October 31.

## Discovery

Search NVD CVE API 2.0 separately for every alias, respecting public request pacing. Save full responses, metadata, totalResults and resultsPerPage. The submitted responses fit one page each; loading asserts completeness. Extract vulnerable CPE families for scoped products and query virtualMatchString for each. Save CPE query definitions and results. Union and deduplicate (product,CVE ID) pairs after date filtering. Retain unrelated candidates in the audit ledger.

## Validation

Fetch each in-window candidate's primary CNA JSON from CVEProject/cvelistV5. A candidate needs an exact scoped affected-product identifier, matching vulnerable CPE or disclosure in the exact upstream repository. Merely mentioning the product is insufficient. A known excluded variant overrides a loose CPE match. For AutoGPT, the original vendor identity excludes a same-named third-party fork.

A referenced disclosure must be retrieved successfully and contain the CVE ID or product marker. Sources include upstream GitHub advisories/issues, coordinated Huntr disclosures, vendor advisories and original-researcher reports. Generic project homepages and source-code blobs alone are insufficient. Original researcher Gists or reports linked by the CVE can be evidence when independent product attribution exists. The automated marker check is deliberately documented and is not a semantic proof or manual audit. Human inspection can still improve it.

Legacy hwchase17/langchain issue URLs are resolved to the same issue number under langchain-ai/langchain. Huntr's HTML is a loading shell; public getVulnerability read responses were retrieved through the page's public read action. Their content-type and read-action ID are recorded. No authentication bypass, vulnerability exploitation or active testing of products was performed. Scripts never execute disclosure payloads.

Rejected NVD/CNA records are excluded. Product-attributed candidates lacking adequate retrievable disclosure evidence are unresolved, not confirmed. Zero excluded-rejected rows means none occurred in this discovery sample, not that the registry has no rejected records.

## Counting and severity

Primary unit: distinct (product,CVE ID). A cross-product CVE may count once in each product and once in the overall distinct-ID total. No weighting for versions or number of advisories. All seven products remain in summary tables, including a hypothetical zero.

CVSS 3.1 only: use NVD-authored metrics if present, otherwise Primary metrics, then source name and vector string for deterministic tie-breaking. Do not select maximum severity opportunistically. Unknown means no 3.1 metric in the saved NVD record. High is [7,9); Critical is [9,10]. Percentages use scored records per product. CVSS 3.0/4.0 are not pooled. CNA metrics are taken from NVD's contributed metric fields, not silently supplemented from a different dataset.

The NVD-only sensitivity column repeats High/Critical counting using NVD-authored 3.1 metrics. Different coverage is expected; this is not a like-for-like risk comparison. Unresolved bounds add all discovered pending associations to confirmed counts. These are evidence bounds, not probability intervals or bounds on undiscovered CVEs.

## Missingness and inference

Report missing CVSS and valid CWE separately. EPSS and epss_date remain empty because exploitation prediction is outside RQ5; C/I/A are retained when a selected metric provides them. No fabricated or imputed values are used.

No causal claim, significance test, vulnerability rate or bootstrap interval is justified by a purposive registry sample with no exposure denominator. Popularity, age, reporting culture, researcher attention, component boundaries, NVD enrichment and discovery gaps affect counts. An automatically confirmed association is an operational classification with inspectable evidence, not infallible truth. All conclusions are restricted to the verified discovered sample.

## Reproducibility

The notebook builds its dataframe again from saved NVD/CNA/disclosure evidence rather than trusting a precomputed CSV. Every included advisory has its complete response body and SHA-256 checksum. Source bodies are stored together with all NVD/CNA records in data/evidence.tar.xz. Original per-file gzip wrappers are removed before packing; the underlying disclosure bytes are preserved. Snapshot paths are updated to the automatically expanded local cache. source_manifest.json hashes every archive member, and evidence_archive.sha256 authenticates the archive against accidental alteration. The loader validates members before writing them into an ignored local cache. Content hashes refer to the UTF-8 response text saved by the collector. Report and charts are generated from the same analysis module. Offline tests check counting, threshold boundaries, score selection, attribution, source completeness and checksum integrity. The submitted compact archive retains all 1,945 source files; only the storage format and local evidence paths change. Online recollection can change results; it must go into a separate directory and never silently replace the submitted snapshot.
