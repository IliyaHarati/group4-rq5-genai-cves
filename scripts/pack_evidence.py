from pathlib import Path
import gzip,hashlib,json,tarfile,io
ROOT=Path.cwd();raw=ROOT/'data/raw'
if not raw.is_dir():
 raise SystemExit('Packing requires collected data/raw sources. Use the existing archive for ordinary analysis.')
entries=[]
for p in sorted(raw.rglob('*')):
 if not p.is_file():continue
 name=p.relative_to(raw).as_posix();body=p.read_bytes()
 if name.endswith('.gz'):
  name=name[:-3];body=gzip.decompress(body)
 if name=='advisory_fetch.json':
  data=json.loads(body)
  for item in data.values():
   if item.get('snapshot'):
    item['snapshot']=item['snapshot'].replace('data/raw/','data/.evidence_cache/').removesuffix('.gz')
  body=json.dumps(data,ensure_ascii=False,indent=2).encode('utf-8')
 entries.append((name,body))
manifest={name:hashlib.sha256(body).hexdigest() for name,body in entries}
(ROOT/'data/source_manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
archive=ROOT/'data/evidence.tar.xz'
with tarfile.open(archive,'w:xz',preset=6) as tar:
 for name,body in entries:
  info=tarfile.TarInfo(name);info.size=len(body);info.mtime=0;info.mode=0o644
  tar.addfile(info,io.BytesIO(body))
sha=hashlib.sha256(archive.read_bytes()).hexdigest()
(ROOT/'data/evidence_archive.sha256').write_text(sha+'  evidence.tar.xz\n',encoding='ascii')
print({'archived_sources':len(entries),'uncompressed_mib':round(sum(len(b) for _,b in entries)/1024**2,2),'archive_mib':round(archive.stat().st_size/1024**2,2)})
