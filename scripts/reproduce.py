"""Rebuild results, figures and notebook from local evidence. No network."""
import sys,json,hashlib,html
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import nbformat as nbf
from src.analysis import CONFIG,build_dataset,summarize,load_records
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':11,'axes.spines.top':False,'axes.spines.right':False,'axes.spines.left':False,'axes.edgecolor':'#cbd5e1','text.color':'#132c42','axes.labelcolor':'#132c42','xtick.color':'#526478','ytick.color':'#132c42','figure.facecolor':'white','axes.facecolor':'white','savefig.facecolor':'white'})

def figures(df,s):
    dest=ROOT/'reports/figures';dest.mkdir(parents=True,exist_ok=True)
    def save(fig,name):
        for ext in ('png','svg'):fig.savefig(dest/(name+'.'+ext),dpi=180,bbox_inches='tight')
        plt.close(fig)
    d=s.iloc[::-1];y=np.arange(len(d))
    fig,ax=plt.subplots(figsize=(11.5,6.4))
    ax.barh(y+.17,d.total_cves,height=.29,color='#167c87',label='All confirmed CVEs')
    ax.barh(y-.17,d.high_critical,height=.29,color='#e57b50',label='High / Critical (CVSS 3.1 ≥ 7.0)')
    for i,(_,r) in enumerate(d.iterrows()):
        ax.text(r.total_cves+2,i+.17,str(r.total_cves),va='center',fontsize=10,fontweight='bold')
        ax.text(r.high_critical+2,i-.17,str(r.high_critical),va='center',fontsize=10)
    ax.set(yticks=y,yticklabels=d['product'],xlabel='Distinct CVE IDs per product',xlim=(0,max(d.total_cves)*1.20))
    ax.set_title('Reported vulnerabilities in selected GenAI products',loc='left',fontweight='bold',fontsize=18,pad=20)
    ax.xaxis.grid(True,color='#edf1f5');ax.set_axisbelow(True);ax.legend(frameon=False,loc='lower right',fontsize=9)
    fig.text(.125,.005,'Published 2023-01-01–2026-10-31  •  Snapshot 2026-11-11  •  Unknown CVSS excluded from High/Critical\nSource: NVD + linked disclosures. Counts describe reporting, not intrinsic security.',fontsize=9,color='#526478')
    fig.subplots_adjust(bottom=.17,left=.17);save(fig,'01_product_ranking')
    colors={'Critical':'#ae3b54','High':'#e57b50','Medium':'#e8ba62','Low':'#72ac9d','None':'#d3dce3','Unknown':'#a9b6c3'}
    counts=pd.crosstab(df['product'],df['severity']).reindex(index=s['product'],columns=list(colors),fill_value=0).fillna(0)
    fig,ax=plt.subplots(figsize=(11.5,6.2));left=np.zeros(len(counts))
    for col,color in colors.items():
        vals=counts[col].to_numpy(dtype=float);ax.barh(np.arange(len(counts)),vals,left=left,label=col,color=color,height=.56)
        for i,v in enumerate(vals):
            if v>=7:ax.text(left[i]+v/2,i,str(int(v)),ha='center',va='center',fontsize=9,color='white' if col=='Critical' else '#132c42')
        left+=vals
    ax.set(yticks=np.arange(len(counts)),yticklabels=counts.index,xlabel='Distinct CVE IDs per product');ax.invert_yaxis()
    ax.set_title('Severity coverage is part of the result',loc='left',fontsize=18,fontweight='bold',pad=20)
    ax.legend(ncols=3,frameon=False,loc='lower right',fontsize=9);ax.xaxis.grid(True,color='#edf1f5');ax.set_axisbelow(True)
    fig.text(.13,.005,'CVSS 3.1 only. NVD preferred, then Primary metric, then deterministic source order.\nUnknown = no CVSS 3.1 metric in the saved NVD record; it does not mean safe.',fontsize=9,color='#526478')
    fig.subplots_adjust(bottom=.18,left=.17,top=.82);save(fig,'02_severity_coverage')
    fig,ax=plt.subplots(figsize=(10.5,6));d=s.iloc[::-1];ys=np.arange(len(d))
    ax.hlines(ys,d.total_cves,d.upper_bound_with_unresolved,color='#a9b6c3',linewidth=5,label='If all unresolved candidates were confirmed')
    ax.scatter(d.total_cves,ys,color='#167c87',s=65,zorder=3,label='Confirmed count')
    ax.scatter(d.upper_bound_with_unresolved,ys,color='#e57b50',marker='|',s=180,zorder=3)
    for i,(_,r) in enumerate(d.iterrows()):ax.text(r.upper_bound_with_unresolved+2,i,f'{r.total_cves} + {r.unresolved_pairs} pending',va='center',fontsize=9)
    ax.set(yticks=ys,yticklabels=d['product'],xlabel='Distinct CVE IDs per product',xlim=(0,max(d.upper_bound_with_unresolved)*1.25))
    ax.set_title('Does unresolved evidence change the ranking?',loc='left',fontsize=17,fontweight='bold',pad=18)
    ax.legend(frameon=False,loc='lower right',fontsize=8);ax.xaxis.grid(True,color='#edf1f5');ax.set_axisbelow(True)
    fig.text(.13,.005,'Evidence bounds, not statistical confidence intervals. Only discovered unresolved candidates are covered.\nUndiscovered CVEs, reporting bias and incorrect source records remain outside these bounds.',fontsize=9,color='#526478')
    fig.subplots_adjust(bottom=.18,left=.19);save(fig,'03_evidence_bounds')

def notebook():
    md=nbf.v4.new_markdown_cell;code=nbf.v4.new_code_cell
    cells=[md('''# RQ5 · Reported CVEs in selected Generative AI products
### Group 4 | زبان تخصصی
**ایلیا هراتی · معین رحیمی · فاطمه نظری · ریحانه شیری · پوریا اسلامی**

**Question:** Which selected products have the most reported CVEs and the most High/Critical cases?

**Published:** 2023-01-01–2026-10-31. **Evidence snapshot:** 2026-11-11.

> A larger reported CVE count is not proof that a product is less secure.

Run every cell in order. This notebook uses committed local evidence and needs no API key or network. Setup is in README.md.'''),
    md('''## 1 · Design before results
All seven core products from the brief are included. Optional products are excluded to keep a fixed product set. Package boundaries and aliases are recorded in config.json.

The counting unit is one **distinct (product, CVE ID) pair**. A CVE affecting two products contributes once to each, but once to the overall distinct-ID count. Versions, aliases and multiple advisories never inflate counts. Dates come from NVD published, not the CVE identifier.

We use **CVSS 3.1 only**: prefer NVD-authored scores, then Primary metrics, then source and vector in lexical order. We never choose the largest available score. High = 7.0–8.9; Critical = 9.0–10.0. Missing scores remain Unknown.'''),
    code('''from pathlib import Path
import sys
ROOT = Path.cwd()
if not (ROOT / 'config.json').exists(): ROOT = ROOT.parent
assert (ROOT / 'config.json').exists(), 'Run from the repository or notebooks directory.'
sys.path.insert(0, str(ROOT))
import pandas as pd
from IPython.display import display, Image, Markdown
from src.analysis import CONFIG, build_dataset, summarize
pd.set_option('display.max_columns', 20)
display(pd.DataFrame(CONFIG['products'])[['name','vendor','repo','scope']])'''),
    md('''## 2 · Discovery, attribution and disclosure validation
NVD keyword searches discover candidates. Supplementary CPE-family queries check mapped affected products. Every raw response is saved in the losslessly compressed evidence archive. It expands automatically into an ignored local cache on first use.

An exact scoped affected-product identifier in CNA metadata, a matching vulnerable CPE or a disclosure in the exact upstream repository establishes attribution. A linked upstream/vendor/coordinated disclosure must also be retrieved successfully and contain the CVE ID or a product marker. This is an automated evidence check, not a claim of manual expert review.

Rejected records and unrelated matches are excluded. Product-associated candidates without sufficient retrievable advisory evidence remain unresolved. Each included row links its disclosure and local evidence snapshot.'''),
    code('''df, audit = build_dataset()
summary = summarize(df, audit)
assert not df.duplicated(['product','cve_id']).any()
assert df.validation_status.eq('confirmed').all()
assert pd.to_datetime(df.published).ge('2023-01-01').all()
assert pd.to_datetime(df.published).lt('2026-11-01').all()
assert df.cvss_version.dropna().isin(['3.1','']).all()
print(f'{len(df):,} confirmed product–CVE pairs; {df.cve_id.nunique():,} distinct CVE IDs.')
display(audit.groupby(['product','validation_status']).size().unstack(fill_value=0))'''),
    md('## 3 · Answer RQ5\nPercentages below use scored CVEs within each product as denominator. All seven products appear even if the observed count is zero.'),
    code('''display(summary[['product','total_cves','high_critical','critical','high','scored_v31','missing_v31','high_critical_pct_scored']])
lead = summary.iloc[0]
hc = summary.sort_values(['high_critical','product'], ascending=[False,True]).iloc[0]
display(Markdown(f"**Most confirmed CVEs:** {lead['product']} ({int(lead['total_cves'])}). **Most High/Critical:** {hc['product']} ({int(hc['high_critical'])})."))
display(Image(filename=str(ROOT / 'reports/figures/01_product_ranking.png')))'''),
    md('## 4 · Severity missingness and scoring-source sensitivity\nThe NVD-only analysis below tests how the High/Critical count depends on source coverage. It is not a second estimate of true risk.'),
    code('''display(Image(filename=str(ROOT / 'reports/figures/02_severity_coverage.png')))
display(summary[['product','high_critical','scored_v31','nvd_only_high_critical','nvd_only_scored']])
display(df.groupby('cvss_source', dropna=False).size().rename('product_cve_pairs'))'''),
    md('## 5 · Unresolved evidence\nThe upper bound adds every discovered unresolved product-associated candidate. These are evidence bounds, not confidence intervals; undiscovered CVEs remain outside the bounds.'),
    code('''display(Image(filename=str(ROOT / 'reports/figures/03_evidence_bounds.png')))
display(summary[['product','total_cves','unresolved_pairs','upper_bound_with_unresolved']])
lead = summary.iloc[0]
robust = all(lead.total_cves > r.upper_bound_with_unresolved for _,r in summary.iloc[1:].iterrows())
print('Confirmed leader robust to all discovered unresolved candidates:', robust)
display(audit[audit.validation_status == 'unresolved_advisory'][['product','cve_id','candidate_advisories']])'''),
    md('## 6 · Inspect the evidence\nOne example per product is selected by CVE ID. The full CSV contains source URLs, retrieval timestamps, SHA-256 values and validation methods.'),
    code('''examples = df.sort_values('cve_id').groupby('product').head(1)
display(examples[['product','cve_id','cvss_score','cvss_source','advisory_url','validation_method']])
display(pd.Series({'CVSS 3.1 missing': int(df.cvss_score.isna().sum()), 'Valid CWE missing': int(df.cwe.fillna('').eq('').sum()), 'EPSS not collected': len(df)},name='product_cve_pairs'))
print('EPSS is outside RQ5. Empty EPSS fields are intentional, not collection failures.')'''),
    md('''## 7 · Interpretation and limitations
- Counts describe reporting, not exploitation likelihood, deployed exposure or intrinsic security.
- Product age, popularity, researcher attention, disclosure policies and component scope differ. There is no shared exposure denominator, so we do not claim a vulnerability rate or causal ranking.
- NVD/CPE coverage and aliases are incomplete. Automated attribution and disclosure checks can miss or misclassify cases. Saved evidence enables inspection; it does not make the process infallible.
- The publication cutoff is fixed, but metrics and evidence use the collection snapshot. This is not a reconstruction of what was known at the cutoff date.
- These seven products form a purposive sample. No significance test or bootstrap interval is claimed.
- CVSS 3.0/4.0-only records remain unscored here. High/Critical severity is not proof of exploitation.

**Takeaway:** Present every count with its date, scope, counting rule and missingness. Do not call the largest bar “the least secure product.”

## References
1. NVD API: https://nvd.nist.gov/developers/vulnerabilities
2. NVD usage: https://nvd.nist.gov/developers/start-here
3. CVE primary records: https://github.com/CVEProject/cvelistV5
4. FIRST CVSS 3.1: https://www.first.org/cvss/v3.1/specification-document
5. Row-level disclosures: data/clean_cves.csv, advisory_url column.

Persian speaking guide: docs/PRESENTATION_FA.md. English dissemination draft: reports/linkedin_post.md.''')]
    nb=nbf.v4.new_notebook(cells=cells,metadata={'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'},'language_info':{'name':'python','version':sys.version.split()[0]}})
    (ROOT/'notebooks').mkdir(exist_ok=True);nbf.write(nb,ROOT/'notebooks/RQ5_Analysis.ipynb')

def report(df,s,audit,flow):
    lead=s.iloc[0];hc=s.sort_values(['high_critical','product'],ascending=[False,True]).iloc[0]
    def svg(name):
        t=(ROOT/'reports/figures'/name).read_text(encoding='utf-8');return t[t.index('<svg'):]
    rows=''.join('<tr>'+''.join(f'<td>{html.escape(str(r[k]))}</td>' for k in ['product','total_cves','high_critical','scored_v31','missing_v31','unresolved_pairs'])+'</tr>' for _,r in s.iterrows())
    examples=''.join(f'<li><strong>{html.escape(r['product'])}</strong> · <a href="{html.escape(r.advisory_url)}">{r.cve_id}</a> · {r.validation_method.replace("_"," ")}</li>' for _,r in df.sort_values('cve_id').groupby('product').head(1).iterrows())
    text=f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RQ5 · GenAI Vulnerability Reporting | Group 4</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#f2f5f7;color:#132c42;font:16px/1.65 system-ui,Segoe UI,Arial,sans-serif}}main{{max-width:1100px;margin:auto;background:white;padding:54px 64px}}.eyebrow{{letter-spacing:.16em;font-size:12px;font-weight:800;color:#167c87;text-transform:uppercase}}h1{{font-size:clamp(36px,5vw,61px);line-height:1.08;letter-spacing:-.045em;margin:18px 0 24px}}h2{{font-size:27px;letter-spacing:-.02em;margin:46px 0 12px}}p{{max-width:850px}}.sub{{font-size:20px;color:#5a6b7d}}.cards{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:30px 0}}.card{{background:#edf6f6;border-top:3px solid #167c87;padding:20px}}.number{{font-size:36px;font-weight:800;line-height:1.3}}.label,.small{{font-size:13px;color:#5a6b7d}}.note{{padding:18px 22px;border-left:4px solid #e57b50;background:#fff5ef}}svg{{width:100%;height:auto}}table{{border-collapse:collapse;width:100%;font-size:14px;margin:20px 0}}th{{text-align:left;background:#132c42;color:white;padding:12px}}td{{padding:11px 12px;border-bottom:1px solid #e2e8ed}}tr:nth-child(even){{background:#f5f8fa}}a{{color:#167c87}}.team{{direction:rtl;text-align:left;font-size:15px}}footer{{margin-top:50px;border-top:1px solid #dce4ea;padding-top:20px;color:#5a6b7d;font-size:13px}}li{{margin:8px 0}}.overflow{{overflow-x:auto}}@media(max-width:700px){{main{{padding:28px 20px}}.cards{{grid-template-columns:1fr}}}}@media print{{body{{background:white}}main{{padding:0;max-width:none}}h2{{break-after:avoid}}svg,.cards,table{{break-inside:avoid}}}}</style>
<main><div class="eyebrow">Research brief 05 / Group 04 / زبان تخصصی</div><h1>Counting disclosures.<br>Keeping the evidence.</h1><p class="sub">Which selected Generative AI products have the most reported CVEs?</p><p class="small">Published 1 Jan 2023–31 Oct 2026 · Evidence collected 11 Nov 2026 · CVSS 3.1</p><div class="team">ایلیا هراتی · معین رحیمی · فاطمه نظری · ریحانه شیری · پوریا اسلامی</div>
<div class="cards"><div class="card"><div class="number">{df.cve_id.nunique()}</div><div class="label">Distinct confirmed CVE IDs</div></div><div class="card"><div class="number">{len(df)}</div><div class="label">Confirmed product–CVE pairs across 7 products</div></div><div class="card"><div class="number">{int(s.high_critical.sum())}</div><div class="label">High/Critical pairs; {int(s.scored_v31.sum())} scored</div></div></div>
<div class="note"><strong>The answer:</strong> {lead['product']} has the largest confirmed CVE count ({lead['total_cves']}). {hc['product']} has the largest confirmed High/Critical count ({hc['high_critical']}). These counts describe reporting in this defined sample, not intrinsic security.</div>
<h2>01 / The product comparison</h2>{svg('01_product_ranking.svg')}<div class="overflow"><table><thead><tr><th>Product</th><th>All CVEs</th><th>High/Critical</th><th>Scored 3.1</th><th>Missing 3.1</th><th>Unresolved</th></tr></thead><tbody>{rows}</tbody></table></div><p class="small">Unit: one distinct product–CVE pair. Cross-product sums need not equal distinct CVE IDs. Unknown CVSS is excluded from High/Critical counts.</p>
<h2>02 / The evidence funnel</h2><p>{flow['unique_discovered_cves']} distinct CVEs were discovered before filtering by date; {flow['candidate_pairs']} product–CVE candidates fell within the publication window. The ledger records {flow['confirmed_pairs']} confirmed, {flow['unrelated_pairs']} unrelated, {flow['rejected_pairs']} rejected and {flow['unresolved_pairs']} unresolved pairs.</p><p>NVD keywords and supplementary CPE-family queries discover candidates. Exact scoped affected-product metadata, vulnerable CPEs or exact upstream repository disclosures establish attribution. Linked disclosures must be retrievable and contain a CVE ID or product marker. Raw NVD responses, CNA records, disclosure snapshots in the compressed evidence archive and the audit ledger are retained.</p>
<h2>03 / Severity coverage</h2>{svg('02_severity_coverage.svg')}<p>NVD-authored CVSS 3.1 metrics take priority; otherwise Primary metrics and a deterministic source order are used. The exported summary also gives NVD-only counts. Unknown severity stays visible.</p>
<h2>04 / Unresolved evidence</h2>{svg('03_evidence_bounds.svg')}<p>Bounds add all discovered unresolved candidates. They are not confidence intervals and cannot account for undiscovered CVEs.</p>
<h2>05 / Follow the evidence</h2><p>One example per product, chosen by CVE ID:</p><ul>{examples}</ul><p class="small">Every confirmed CSV row has advisory and NVD links, a validation method, retrieval timestamp and snapshot checksum. Verification is automated and inspectable; it is not a claim of manual expert review.</p>
<h2>06 / Interpretation</h2><p>These are reporting counts in a purposively selected product set. Product age, popularity, deployment exposure, researcher attention, disclosure policies and component scope differ. No common exposure denominator is available. A larger bar therefore does not establish a higher vulnerability rate or lower intrinsic security.</p><p>NVD/CPE coverage and aliases can be incomplete, and automated verification can miss or misclassify cases. The publication cutoff is fixed; source records and metrics use the collection snapshot. EPSS, exploitation evidence and CVSS 4.0 are outside the primary analysis.</p>
<footer><a href="https://nvd.nist.gov/developers/vulnerabilities">NIST NVD API 2.0</a> · <a href="https://github.com/CVEProject/cvelistV5">CVE Program records</a> · <a href="https://www.first.org/cvss/v3.1/specification-document">FIRST CVSS 3.1</a> · linked disclosures.<br>Reproduce: python scripts/reproduce.py. Machine-assisted collection and analysis; group members should review the notebook before presenting.</footer></main></html>'''
    (ROOT/'reports/RQ5_Report.html').write_text(text,encoding='utf-8')
    post=f'''# LinkedIn draft — Group 4

Which Generative AI products have the most publicly reported vulnerabilities? Our Group 4 project examined seven selected products: LangChain, Ollama, vLLM, Open WebUI, Flowise, Langflow and AutoGPT.

Using NVD publication dates from January 2023 through October 2026 and an evidence snapshot collected on 11 November 2026, we confirmed {len(df)} product–CVE pairs, representing {df.cve_id.nunique()} distinct CVE IDs. {lead['product']} had the largest confirmed count, with {int(lead['total_cves'])} CVEs. The largest High/Critical count belonged to {hc['product']}, with {int(hc['high_critical'])} CVEs scored at least 7.0 under our CVSS 3.1 selection policy.

The hardest part was attribution. A product name in a description was not enough: we checked affected-product evidence and linked disclosures, removed unrelated matches, deduplicated identifiers and kept unresolved cases visible. Our repository includes an executable notebook, clean CSV, audit ledger, saved source evidence and reproducible charts.

These are reporting counts, not a security league table. Product age, scope, popularity, researcher attention, incomplete coverage and missing scores limit interpretation. We therefore report severity coverage and unresolved-evidence bounds alongside the ranking.

Our takeaway: a defensible comparison needs more than a bar chart. Every number needs a clear counting rule, a date and an inspectable evidence trail.

#GenerativeAI #Cybersecurity #CVE #DataAnalysis #ReproducibleResearch
'''
    assert 150<=len(post.split('\n\n',1)[1].split())<=250
    (ROOT/'reports/linkedin_post.md').write_text(post,encoding='utf-8')
    findings=f"# RQ5 findings\n\nSnapshot: 2026-11-11. Published: 2023-01-01–2026-10-31.\n\nMost confirmed CVEs: **{lead['product']} ({lead['total_cves']})**. Most High/Critical: **{hc['product']} ({hc['high_critical']})**.\n\n{df.cve_id.nunique()} distinct IDs; {len(df)} product–CVE pairs; {int(s.scored_v31.sum())} scored pairs; {int(s.missing_v31.sum())} missing scores; {flow['unresolved_pairs']} unresolved pairs excluded from the primary comparison.\n\nCounts measure reporting in the verified discovered sample, not intrinsic product security.\n"
    (ROOT/'reports/FINDINGS.md').write_text(findings,encoding='utf-8')

def main():
    df,audit=build_dataset();s=summarize(df,audit)
    assert not df.duplicated(['product','cve_id']).any()
    df.to_csv(ROOT/'data/clean_cves.csv',index=False,encoding='utf-8-sig');audit.to_csv(ROOT/'data/validation_ledger.csv',index=False,encoding='utf-8-sig');s.to_csv(ROOT/'data/product_summary.csv',index=False,encoding='utf-8-sig')
    flow={'unique_discovered_cves':len(load_records()),'candidate_pairs':len(audit),'confirmed_pairs':len(df),'unique_confirmed_cves':df.cve_id.nunique(),'unrelated_pairs':int(audit.validation_status.eq('excluded_unrelated').sum()),'rejected_pairs':int(audit.validation_status.eq('excluded_rejected').sum()),'unresolved_pairs':int(audit.validation_status.eq('unresolved_advisory').sum())}
    (ROOT/'data/flow_counts.json').write_text(json.dumps(flow,indent=2),encoding='utf-8')
    figures(df,s);notebook();report(df,s,audit,flow)
    print(s.to_string(index=False));print(json.dumps(flow));print('Offline rebuild complete.')
if __name__=='__main__':main()
