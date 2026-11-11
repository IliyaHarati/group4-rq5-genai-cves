"""RQ5: deterministic, conservative product attribution and CVSS 3.1 analysis."""
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlparse
import pandas as pd
from src.evidence import evidence_root

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / 'config.json').read_text(encoding='utf-8'))

def norm(value):
    return re.sub(r'[^a-z0-9]', '', str(value).lower())

def official_repo(url, product):
    p = urlparse(url)
    if p.hostname not in {'github.com', 'www.github.com'}:
        return False
    parts = p.path.lower().strip('/').split('/')
    return '/'.join(parts[:2]) in CONFIG['repos'][product]

def directly_affected(cna, product):
    allowed = {norm(x) for x in CONFIG['identifiers'][product]}
    owners = {repo.split('/')[0] for repo in CONFIG['repos'][product]}
    for a in cna.get('affected', []):
        values = [a.get('product', ''), a.get('packageName', '')]
        values += [v.split('/')[-1] for v in values if '/' in v and not v.startswith('@')]
        vendor = norm(a.get('vendor', ''))
        if not any(norm(v) in allowed for v in values):
            continue
        if product == 'AutoGPT' and vendor not in {norm(x) for x in owners}:
            continue
        if product == 'LangChain' and norm(a.get('product')) in {'redis','mongodb','helm'} and vendor not in {'langchain','langchainai'}:
            continue
        if a.get('versions') and not any(v.get('status') == 'affected' for v in a['versions']) and a.get('defaultStatus') != 'affected':
            continue
        return True
    return False

def cpe_evidence(cve, product):
    allowed = {norm(x) for x in CONFIG['identifiers'][product]}
    found = []
    def visit(value):
        if isinstance(value, dict):
            if value.get('vulnerable') and value.get('criteria', '').startswith('cpe:2.3:a:'):
                parts = value['criteria'].split(':')
                if len(parts) > 4 and norm(parts[4]) in allowed:
                    # AutoGPT forks must have the official owner as vendor.
                    if product != 'AutoGPT' or norm(parts[3]) == 'significantgravitas':
                        found.append(value['criteria'])
            for child in value.values(): visit(child)
        elif isinstance(value, list):
            for child in value: visit(child)
    visit(cve.get('configurations', []))
    return sorted(set(found))

def advisory_options(cve, cna, product):
    urls = sorted({r['url'].rstrip('/') for r in cve.get('references', []) + cna.get('references', []) if r.get('url')})
    direct = directly_affected(cna, product) or bool(cpe_evidence(cve, product))
    result = []
    for u in urls:
        p = urlparse(u)
        if official_repo(u, product) and any(x in p.path for x in ['/security/advisories/', '/issues/', '/pull/', '/discussions/']):
            result.append((0 if '/security/advisories/' in p.path else 2, u, 'official_repository_disclosure'))
        elif direct and p.hostname in {'huntr.com','huntr.dev'} and '/bounties/' in p.path:
            result.append((1, u, 'coordinated_disclosure'))
        elif direct and p.hostname in {'www.ibm.com','ibm.com'} and '/support/' in p.path:
            result.append((1, u, 'vendor_advisory'))
        elif direct and p.hostname == 'github.com' and '/advisories/GHSA-' in p.path:
            result.append((2, u, 'github_advisory_database'))
        elif direct and p.hostname in {'securitylab.github.com','tenable.com','www.tenable.com','research.jfrog.com','www.zerodayinitiative.com','zerodayinitiative.com','cert.pl','kb.cert.org','www.kb.cert.org','www.vulncheck.com','vulncheck.com','research.nccgroup.com','oligo.security','www.oligo.security','security.snyk.io','www.mend.io','a1batr0ss.top','aisec.today','www.obsidiansecurity.com'} and len(p.path.strip('/')) > 8:
            result.append((3, u, 'researcher_or_coordination_advisory'))
        elif direct and p.hostname == 'gist.github.com' and len(p.path.strip('/').split('/')) >= 2:
            result.append((4, u, 'researcher_disclosure'))
        elif direct and p.hostname == 'github.com' and not official_repo(u, product) and ('/blob/' in p.path or re.search(r'/[^/]*CVE-\d{4}-\d+',p.path,re.I)):
            result.append((4, u, 'researcher_disclosure'))
    for priority, url, kind in list(result):
        if 'github.com/hwchase17/langchain/' in url:
            result.append((priority, url.replace('github.com/hwchase17/langchain/', 'github.com/langchain-ai/langchain/'), kind))
    return sorted(result)

def select_metric(cve, nvd_only=False):
    metrics = [m for m in cve.get('metrics', {}).get('cvssMetricV31', []) if m.get('cvssData', {}).get('version') == '3.1']
    if nvd_only:
        metrics = [m for m in metrics if m.get('source') == 'nvd@nist.gov']
    if not metrics: return None
    return sorted(metrics, key=lambda m:(m.get('source') != 'nvd@nist.gov', m.get('type') != 'Primary', m.get('source',''), m.get('cvssData',{}).get('vectorString','')))[0]

def severity(score):
    if pd.isna(score): return 'Unknown'
    if score >= 9: return 'Critical'
    if score >= 7: return 'High'
    if score >= 4: return 'Medium'
    if score > 0: return 'Low'
    return 'None'

def load_records():
    records = {}
    for file in sorted(evidence_root().glob('nvd_*.json')):
        obj = json.loads(file.read_text(encoding='utf-8'))
        assert len(obj['vulnerabilities']) == obj['totalResults'], f'Incomplete pagination: {file}'
        records.update({v['cve']['id']:v['cve'] for v in obj['vulnerabilities']})
    return records

def candidate_rows():
    records = load_records()
    pairs = json.loads((evidence_root() / 'candidate_pairs.json').read_text(encoding='utf-8'))
    result = []
    for pair in pairs:
        cve = records[pair['cve_id']]
        cnafile = evidence_root() / 'cna' / (pair['cve_id']+'.json')
        doc = json.loads(cnafile.read_text(encoding='utf-8')) if cnafile.exists() else {}
        cna = doc.get('containers',{}).get('cna',{})
        product = pair['product']
        rejected = cve.get('vulnStatus') == 'Rejected' or doc.get('cveMetadata',{}).get('state') == 'REJECTED'
        direct = directly_affected(cna, product)
        cpes = cpe_evidence(cve, product)
        options = advisory_options(cve, cna, product)
        # A matching upstream disclosure is evidence even in older CNA records with n/a fields.
        repo_disclosure = any(kind == 'official_repository_disclosure' for _,_,kind in options)
        out_of_scope = product == 'Langflow' and any(norm(a.get('product','')) == 'langflowdesktop' for a in cna.get('affected',[])) and not direct
        attribution = (direct or bool(cpes) or repo_disclosure) and not out_of_scope
        result.append({**pair,'rejected':rejected,'attributed':attribution,'direct_affected':direct,'cpes':cpes,'options':options,'cna_title':cna.get('title','')})
    return result

def build_dataset():
    records = load_records()
    evidencefile = evidence_root() / 'advisory_fetch.json'
    evidence = json.loads(evidencefile.read_text(encoding='utf-8')) if evidencefile.exists() else {}
    audit, rows = [], []
    for item in candidate_rows():
        cve = records[item['cve_id']]
        selected = None
        for _,url,kind in item['options']:
            e = evidence.get(url,{})
            # Actual retrieval plus CVE ID or product marker in the disclosure text.
            if e.get('ok') and (item['cve_id'] in e.get('cve_ids',[]) or item['product'] in e.get('product_markers',[])):
                selected = (url,kind,e)
                break
        if item['rejected']: status='excluded_rejected'
        elif not item['attributed']: status='excluded_unrelated'
        elif selected: status='confirmed'
        else: status='unresolved_advisory'
        audit.append({'cve_id':item['cve_id'],'product':item['product'],'validation_status':status,'direct_affected':item['direct_affected'],'cpe_match':bool(item['cpes']),'cna_title':item['cna_title'],'candidate_advisories':' | '.join(u for _,u,_ in item['options'])})
        if status != 'confirmed': continue
        metric=select_metric(cve)
        data=metric.get('cvssData',{}) if metric else {}
        score=data.get('baseScore',float('nan'))
        nvd=select_metric(cve,nvd_only=True)
        cwes=sorted({d['value'] for w in cve.get('weaknesses',[]) for d in w.get('description',[]) if re.fullmatch(r'CWE-\d+',d.get('value',''))})
        description=next((d['value'] for d in cve.get('descriptions',[]) if d.get('lang')=='en'),'')
        url,kind,e=selected
        group=next(p['group'] for p in CONFIG['products'] if p['name']==item['product'])
        rows.append({'cve_id':item['cve_id'],'product':item['product'],'group':group,'published':cve['published'],'last_modified':cve.get('lastModified',''),'nvd_status':cve.get('vulnStatus',''),'cwe':' | '.join(cwes),'cvss_version':'3.1' if metric else '', 'cvss_score':score,'severity':severity(score),'cvss_source':metric.get('source','') if metric else '', 'cvss_vector':data.get('vectorString',''),'C':data.get('confidentialityImpact',''),'I':data.get('integrityImpact',''),'A':data.get('availabilityImpact',''),'epss':'','epss_date':'','advisory_url':url,'validation_status':'confirmed','validation_method':kind,'affected_product_evidence':'CNA affected + disclosure' if item['direct_affected'] else 'upstream disclosure + CPE' if item['cpes'] else 'upstream disclosure','cpe_matches':' | '.join(item['cpes']),'nvd_url':'https://nvd.nist.gov/vuln/detail/'+item['cve_id'],'cna_url':'https://www.cve.org/CVERecord?id='+item['cve_id'],'advisory_snapshot':e['snapshot'],'advisory_sha256':e['sha256'],'retrieved_at':e['retrieved_at'],'nvd_only_score':nvd['cvssData']['baseScore'] if nvd else float('nan'),'description':description})
    df=pd.DataFrame(rows).sort_values(['product','cve_id']).reset_index(drop=True)
    return df,pd.DataFrame(audit).sort_values(['product','cve_id']).reset_index(drop=True)

def summarize(df,audit):
    rows=[]
    for product in [p['name'] for p in CONFIG['products']]:
        d=df[df['product']==product]; a=audit[audit['product']==product]
        n=len(d);scored=d['cvss_score'].notna().sum();hc=(d['cvss_score']>=7).sum()
        unresolved=(a['validation_status']=='unresolved_advisory').sum()
        rows.append({'product':product,'total_cves':n,'high_critical':int(hc),'critical':int((d['cvss_score']>=9).sum()),'high':int(((d['cvss_score']>=7)&(d['cvss_score']<9)).sum()),'scored_v31':int(scored),'missing_v31':int(n-scored),'high_critical_pct_scored':round(100*hc/scored,2) if scored else None,'unresolved_pairs':int(unresolved),'upper_bound_with_unresolved':n+int(unresolved),'nvd_only_high_critical':int((d['nvd_only_score']>=7).sum()),'nvd_only_scored':int(d['nvd_only_score'].notna().sum())})
    return pd.DataFrame(rows).sort_values(['total_cves','product'],ascending=[False,True]).reset_index(drop=True)

if __name__=='__main__':
    candidates=candidate_rows()
    print(pd.DataFrame(candidates).groupby('product')[['attributed','rejected']].sum().to_string())
