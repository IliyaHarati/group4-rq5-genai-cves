# LinkedIn draft — Group 4

Which Generative AI products have the most publicly reported vulnerabilities? Our Group 4 project examined seven selected products: LangChain, Ollama, vLLM, Open WebUI, Flowise, Langflow and AutoGPT.

Using NVD publication dates from January 2023 through October 2026 and an evidence snapshot collected on 11 November 2026, we confirmed 791 product–CVE pairs, representing 791 distinct CVE IDs. Langflow had the largest confirmed count, with 223 CVEs. The largest High/Critical count belonged to Langflow, with 157 CVEs scored at least 7.0 under our CVSS 3.1 selection policy.

The hardest part was attribution. A product name in a description was not enough: we checked affected-product evidence and linked disclosures, removed unrelated matches, deduplicated identifiers and kept unresolved cases visible. Our repository includes an executable notebook, clean CSV, audit ledger, saved source evidence and reproducible charts.

These are reporting counts, not a security league table. Product age, scope, popularity, researcher attention, incomplete coverage and missing scores limit interpretation. We therefore report severity coverage and unresolved-evidence bounds alongside the ranking.

Our takeaway: a defensible comparison needs more than a bar chart. Every number needs a clear counting rule, a date and an inspectable evidence trail.

#GenerativeAI #Cybersecurity #CVE #DataAnalysis #ReproducibleResearch
