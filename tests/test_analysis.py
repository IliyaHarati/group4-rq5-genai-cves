import hashlib,json
from src.evidence import evidence_root
from pathlib import Path
import pandas as pd
import pytest
from src.analysis import ROOT,CONFIG,severity,select_metric,directly_affected,official_repo,build_dataset,summarize

@pytest.mark.parametrize('value,expected',[(float('nan'),'Unknown'),(0,'None'),(.1,'Low'),(3.9,'Low'),(4,'Medium'),(6.9,'Medium'),(7,'High'),(8.9,'High'),(9,'Critical'),(10,'Critical')])
def test_severity_boundaries(value,expected):
    assert severity(value)==expected

def test_nvd_preferred_over_higher_cna_score():
    c={'metrics':{'cvssMetricV31':[{'source':'cna@example.org','type':'Primary','cvssData':{'version':'3.1','baseScore':9.9}},{'source':'nvd@nist.gov','type':'Secondary','cvssData':{'version':'3.1','baseScore':7.5}}]}}
    assert select_metric(c)['cvssData']['baseScore']==7.5

def test_v4_is_not_a_v31_fallback():
    assert select_metric({'metrics':{'cvssMetricV40':[{'cvssData':{'version':'4.0','baseScore':10}}]}}) is None

def test_upstream_matching_has_path_boundary():
    assert official_repo('https://github.com/ollama/ollama/security/advisories/GHSA-test','Ollama')
    assert not official_repo('https://github.com/ollama/ollama-fork/issues/1','Ollama')
    assert not official_repo('https://github.com.evil.test/ollama/ollama/issues/1','Ollama')

def test_third_party_names_are_not_the_product():
    assert not directly_affected({'affected':[{'vendor':'Thesamur','product':'AutoGPT'}]},'AutoGPT')
    assert not directly_affected({'affected':[{'vendor':'chatchat-space','product':'Langchain-Chatchat'}]},'LangChain')
    assert not directly_affected({'affected':[{'vendor':'IBM','product':'Langflow Desktop'}]},'Langflow')

@pytest.fixture(scope='module')
def data():return build_dataset()

def test_snapshot_partition_and_unique_pairs(data):
    df,audit=data
    assert not df.duplicated(['product','cve_id']).any()
    assert not audit.duplicated(['product','cve_id']).any()
    assert set(audit.validation_status)<= {'confirmed','excluded_unrelated','excluded_rejected','unresolved_advisory'}
    assert len(df)==audit.validation_status.eq('confirmed').sum()
    assert pd.to_datetime(df.published).ge(CONFIG['start']).all()
    assert pd.to_datetime(df.published).lt(CONFIG['end_exclusive']).all()
    assert not ((df['product']=='Langflow') & (df.cve_id=='CVE-2026-3357')).any()

def test_summary_denominators_and_zero_product(data):
    df,audit=data;s=summarize(df,audit)
    assert set(s['product'])=={p['name'] for p in CONFIG['products']}
    assert s.total_cves.eq(s.scored_v31+s.missing_v31).all()
    assert s.high_critical.le(s.scored_v31).all()
    assert s.high_critical.eq(s.high+s.critical).all()
    empty=summarize(df[df['product']!='Ollama'],audit)
    assert empty.loc[empty['product']=='Ollama','total_cves'].iloc[0]==0

def test_every_confirmed_disclosure_has_valid_saved_bytes(data):
    df,_=data
    for _,r in df.iterrows():
        body=(ROOT/r.advisory_snapshot).read_bytes()
        assert hashlib.sha256(body).hexdigest()==r.advisory_sha256

def test_all_raw_inputs_match_manifest():
    manifest=json.loads((ROOT/'data/source_manifest.json').read_text(encoding='utf-8'))
    evidence=evidence_root()
    for name,sha in manifest.items():assert hashlib.sha256((evidence/name).read_bytes()).hexdigest()==sha

def test_csv_matches_recomputed_result(data):
    df,_=data;saved=pd.read_csv(ROOT/'data/clean_cves.csv')
    assert set(zip(df['product'],df.cve_id))==set(zip(saved['product'],saved.cve_id))
    assert df.cvss_score.fillna(-1).tolist()==saved.cvss_score.fillna(-1).tolist()
