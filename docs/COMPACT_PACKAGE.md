# Compact evidence package

The compact submission preserves the full content of all 1,945 original evidence files in data/evidence.tar.xz. The individual gzip wrappers have been replaced by one shared compression stream. No CVEs, advisory bodies, source URLs, validation decisions or results were removed.

The notebook and report remain readable immediately. Offline analysis expands the sources into the ignored data/.evidence_cache folder on first execution; allow additional time and roughly 208 MiB of temporary disk space. Subsequent runs reuse the cache. The archive and each source body have SHA-256 checksums.

Do not upload the expanded cache or a legacy data/raw folder. Both are ignored by Git. Submit the compact folder supplied in the ZIP. The same reproduction commands and GitHub workflow apply.
