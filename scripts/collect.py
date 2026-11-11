"""Optional fresh discovery. Never overwrites the submitted snapshot.
Example: python scripts/collect.py --output refresh_2026_11_18
This recollects the original NVD queries and primary CNA records; it does not
claim that historical disclosure read endpoints will stay available.
"""
import argparse,json,time,sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import requests
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.analysis import CONFIG
from src.evidence import evidence_root

def get(url,params=None):
    for attempt in range(4):
        try:
            r=requests.get(url,params=params,timeout=45)
            if r.status_code==429 or r.status_code>=500:
                time.sleep(8*(attempt+1));continue
            r.raise_for_status();return r.json()
        except requests.RequestException:
            if attempt==3:raise
            time.sleep(4*(attempt+1))
    raise RuntimeError('Source unavailable after retry limit: '+url)

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',required=True);args=ap.parse_args()
    dest=Path(args.output).resolve()
    if dest==ROOT or ROOT/'data'==dest or dest.exists():raise SystemExit('Choose a NEW output directory; the submitted snapshot is protected.')
    raw=dest/'data/raw';(raw/'cna').mkdir(parents=True)
    (dest/'config.json').write_text(json.dumps(CONFIG,indent=2),encoding='utf-8')
    specs=[]
    for p in CONFIG['products']:
        for alias in p['aliases']:
            import re
            filename='nvd_'+re.sub('[^a-z0-9]','_',alias)+'.json'
            specs.append((filename,{'keywordSearch':alias},[p['name']]))
    cpes=json.loads((evidence_root()/'cpe_queries.json').read_text(encoding='utf-8'))
    specs += [('nvd_cpe_'+str(i)+'.json',{'virtualMatchString':q['cpe']},q['products']) for i,q in enumerate(cpes)]
    pairs=set();request_log=[]
    for filename,query,products in specs:
        pages=[];start=0
        while True:
            time.sleep(6.2)
            params={**query,'resultsPerPage':2000,'startIndex':start}
            obj=get('https://services.nvd.nist.gov/rest/json/cves/2.0',params)
            pages+=obj['vulnerabilities'];request_log.append({'params':params,'timestamp':obj['timestamp'],'totalResults':obj['totalResults']})
            start+=len(obj['vulnerabilities'])
            if start>=obj['totalResults']:break
            if not obj['vulnerabilities']:raise RuntimeError('Incomplete API pagination')
        obj.update(vulnerabilities=pages,startIndex=0,resultsPerPage=len(pages))
        (raw/filename).write_text(json.dumps(obj),encoding='utf-8')
        for v in pages:
            c=v['cve']
            if CONFIG['start']<=c['published']<CONFIG['end_exclusive']:
                pairs.update((p,c['id']) for p in products)
        print(filename,len(pages))
    (raw/'candidate_pairs.json').write_text(json.dumps([{'product':p,'cve_id':c} for p,c in sorted(pairs)],indent=2),encoding='utf-8')
    def cna(cid):
        _,year,num=cid.split('-');bucket=num[:-3]+'xxx'
        obj=get(f'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}/{cid}.json')
        (raw/'cna'/(cid+'.json')).write_text(json.dumps(obj),encoding='utf-8')
    with ThreadPoolExecutor(max_workers=6) as pool:list(pool.map(cna,sorted({c for _,c in pairs})))
    (raw/'request_log.json').write_text(json.dumps(request_log,indent=2),encoding='utf-8')
    print('Fresh discovery saved. Revalidate disclosures before reporting new results. Original evidence and results are unchanged.')
if __name__=='__main__':main()
