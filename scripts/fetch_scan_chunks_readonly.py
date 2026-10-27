#!/usr/bin/env python3
"""Fetch a manifest's exact immutable chunk references into a private directory."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import gzip
import json
import os
from pathlib import Path

import boto3
from botocore.config import Config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest")
    parser.add_argument("output_dir")
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--kind", choices=("finding_chunks", "finding_index_chunks"), required=True)
    parser.add_argument("--workers", type=int, default=16)
    args = parser.parse_args()
    if not 1 <= args.workers <= 32:
        raise ValueError("workers must be 1..32")
    body = Path(args.manifest).read_bytes()
    manifest = json.loads(gzip.decompress(body) if body.startswith(b"\x1f\x8b") else body)
    refs = [row["reference"] for row in manifest[args.kind]]
    if not refs or len(set(refs)) != len(refs):
        raise ValueError("missing or duplicate manifest references")
    prefix = "/".join(refs[0].split("/")[:2]) + "/"
    suffix = "findings-" if args.kind == "finding_chunks" else "finding-index-"
    if any(not ref.startswith(prefix + suffix) or not ref.endswith(".json")
           or "/" in ref[len(prefix):] for ref in refs):
        raise ValueError("reference escapes scan/kind prefix")
    out = Path(args.output_dir)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(out, 0o700)
    client = boto3.Session(profile_name=args.profile, region_name=args.region).client(
        "s3", config=Config(max_pool_connections=args.workers, read_timeout=120,
                            retries={"max_attempts": 5, "mode": "standard"}))

    def fetch(index, reference):
        path = out / f"{index:04d}.json.gz"
        if path.exists():
            return
        data = client.get_object(Bucket=args.bucket, Key="artifacts/" + reference)["Body"].read()
        # The hosted writer compresses larger chunks; retain the original bytes.
        json.loads(gzip.decompress(data) if data.startswith(b"\x1f\x8b") else data)
        temp = path.with_suffix(".tmp")
        fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.replace(temp, path)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(fetch, i, ref) for i, ref in enumerate(refs)]
        for future in as_completed(futures):
            future.result()
    print(json.dumps({"kind": args.kind, "chunks": len(refs), "scan_prefix": prefix}))


if __name__ == "__main__":
    main()
