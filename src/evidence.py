"""Offline access to the complete, losslessly packed research evidence."""
import hashlib
import json
import tarfile
from functools import lru_cache
from pathlib import Path, PurePosixPath

ROOT=Path(__file__).resolve().parents[1]

@lru_cache(maxsize=1)
def evidence_root():
    """Verify the archive, then expand it once into an ignored local cache."""
    archive=ROOT/'data/evidence.tar.xz'
    expected=(ROOT/'data/evidence_archive.sha256').read_text(encoding='ascii').split()[0]
    actual=hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual!=expected:
        raise ValueError('Evidence archive checksum mismatch. Restore the original archive.')
    cache=ROOT/'data/.evidence_cache'
    marker=cache/'.archive_sha256'
    if marker.exists() and marker.read_text(encoding='ascii').strip()==actual:
        return cache
    manifest=json.loads((ROOT/'data/source_manifest.json').read_text(encoding='utf-8'))
    cache.mkdir(parents=True,exist_ok=True)
    seen=set()
    with tarfile.open(archive,'r:xz') as tar:
        for member in tar:
            name=PurePosixPath(member.name)
            if not member.isfile() or name.is_absolute() or '..' in name.parts or member.name not in manifest:
                raise ValueError('Unexpected evidence archive member: '+member.name)
            stream=tar.extractfile(member)
            body=stream.read()
            if hashlib.sha256(body).hexdigest()!=manifest[member.name]:
                raise ValueError('Evidence source checksum mismatch: '+member.name)
            target=cache.joinpath(*name.parts)
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(body)
            seen.add(member.name)
    if seen!=set(manifest):
        raise ValueError('Evidence archive is incomplete.')
    marker.write_text(actual,encoding='ascii')
    return cache
