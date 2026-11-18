"""ECS containers without a declared user run as their immutable image's USER."""
import gzip
import hashlib
import io
import json
import tarfile
import threading

import pytest

from peaso.checks import CHECKS
from peaso.collectors import aws_ecs_image_user
from peaso.collectors import aws_image_vulnerability_native_20261021 as native
from peaso.collectors import aws_package_content_indicators as content

CHECK = "aws.b.ecs.declared_nonroot_users"
REGISTRY, REGION, REPO = "244541190879", "us-east-1", "cade/api"
ARN = "arn:aws:ecs:us-east-1:123456789012:task-definition/api:7"


def check():
    return next(c for c in CHECKS if c.id == CHECK)


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def image_ref(digest):
    return f"{REGISTRY}.dkr.ecr.{REGION}.amazonaws.com/{REPO}@{digest}"


def layer(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return gzip.compress(buffer.getvalue())


class Registry:
    """A fake ECR registry serving one digest-pinned image."""

    def __init__(self, user, layers):
        self.calls = []
        config = {"architecture": "amd64", "os": "linux", "config": {} if user is None else {"User": user},
                  "rootfs": {"type": "layers", "diff_ids": []}}
        self.config = json.dumps(config).encode()
        self.blobs = {sha(self.config): self.config}
        descriptors = []
        for files in layers:
            raw = layer(files)
            self.blobs[sha(raw)] = raw
            descriptors.append({"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                                "digest": sha(raw), "size": len(raw)})
        manifest = {"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                    "config": {"mediaType": "application/vnd.docker.container.image.v1+json",
                               "digest": sha(self.config), "size": len(self.config)},
                    "layers": descriptors}
        self.manifest = json.dumps(manifest).encode()
        self.digest = sha(self.manifest)

    def client(self, service, region_name=None, config=None):
        assert service == "ecr" and region_name == REGION
        return self

    def close(self):
        pass

    def batch_get_image(self, **arguments):
        self.calls.append(("batch_get_image", arguments["imageIds"][0]["imageDigest"]))
        assert arguments["registryId"] == REGISTRY and arguments["repositoryName"] == REPO
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "failures": [], "images": [{
            "registryId": REGISTRY, "repositoryName": REPO, "imageId": {"imageDigest": self.digest},
            "imageManifest": self.manifest.decode(),
            "imageManifestMediaType": "application/vnd.docker.distribution.manifest.v2+json"}]}

    def get_download_url_for_layer(self, **arguments):
        digest = arguments["layerDigest"]
        self.calls.append(("get_download_url_for_layer", digest))
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "layerDigest": digest, "downloadUrl": digest}


class Requests:
    def __init__(self, enabled=True):
        self._lock = threading.Lock()
        self.calls, self.max_calls, self.deadline, self.timeout, self.workers = 0, None, None, 5, 1
        self.content_secret_scans = enabled
        self.content_secret_scan_kinds = frozenset({"ecr_repository"}) if enabled else frozenset()

    def check_deadline(self):
        pass


@pytest.fixture
def downloads(monkeypatch):
    blobs = {}

    def download(requests, url, region, cap, expected_size=None, budget=None):
        return blobs[url]

    def download_path(requests, url, region, digest, size, path, *, check=None, end=None):
        path.write_bytes(blobs[url])
        return path
    monkeypatch.setattr(content, "download", download)
    monkeypatch.setattr(native, "download_blob_path", download_path)
    return blobs


def task(image, user=None, name="app"):
    row = {"name": name, "image": image}
    if user is not None:
        row["user"] = user
    return {"taskDefinitionArn": ARN, "Definition": {"collection_status": "collected", "taskDefinition": {
        "taskDefinitionArn": ARN, "runtimePlatform": {"operatingSystemFamily": "LINUX"},
        "containerDefinitions": [row]}}}


def enrich_and_check(registry, item, requests=None):
    [enriched] = aws_ecs_image_user.enrich(requests or Requests(), registry, REGION, [item])
    return enriched, check().evaluate(enriched, {})


PASSWD = b"root:x:0:0:root:/root:/sbin/nologin\nnonroot:x:65532:65532:nonroot:/home/nonroot:/sbin/nologin\n"


def test_named_image_user_resolved_through_image_passwd_passes(downloads):
    registry = Registry("nonroot:nonroot", [{"etc/passwd": PASSWD}, {"app/server.js": b"run()"}])
    downloads.update(registry.blobs)
    enriched, (status, evidence) = enrich_and_check(registry, task(image_ref(registry.digest)))
    assert status == "PASS"
    source = evidence["user_sources"]["app"]
    assert source["source"] == "image_config" and source["user"] == "nonroot:nonroot"
    assert source["config_digest"] == sha(registry.config) and source["uid"] == 65532
    assert evidence["proven_numeric_uid_containers"] == ["app"]


def test_each_image_blob_is_read_once_per_scan(downloads):
    registry = Registry("nonroot", [{"etc/passwd": PASSWD}])
    downloads.update(registry.blobs)
    requests = Requests()
    items = [task(image_ref(registry.digest)), {**task(image_ref(registry.digest)),
             "taskDefinitionArn": ARN[:-1] + "6"}]
    items[1]["Definition"]["taskDefinition"]["taskDefinitionArn"] = ARN[:-1] + "6"
    aws_ecs_image_user.enrich(requests, registry, REGION, items)
    aws_ecs_image_user.enrich(requests, registry, REGION, [task(image_ref(registry.digest), name="other")])
    downloaded = [digest for operation, digest in registry.calls if operation == "get_download_url_for_layer"]
    assert sorted(downloaded) == sorted(set(downloaded)) and len(downloaded) == 2


@pytest.mark.parametrize("user,expected", [("", "FAIL"), (None, "FAIL"), ("0:0", "FAIL"), ("root", "FAIL"),
                                           ("1000", "PASS"), ("1000:1000", "PASS")])
def test_image_config_user_decides_when_task_declares_none(downloads, user, expected):
    registry = Registry(user, [{"app/server.js": b"run()"}])
    downloads.update(registry.blobs)
    _, (status, evidence) = enrich_and_check(registry, task(image_ref(registry.digest)))
    assert status == expected
    assert evidence["user_sources"]["app"]["source"] == "image_config"


def test_named_user_missing_from_image_passwd_stays_unknown(downloads):
    registry = Registry("node", [{"etc/passwd": PASSWD}])
    downloads.update(registry.blobs)
    _, (status, evidence) = enrich_and_check(registry, task(image_ref(registry.digest)))
    assert status == "UNKNOWN"
    assert evidence["unresolved_named_users"] == ["app"]
    assert evidence["user_sources"]["app"]["user"] == "node"


def test_named_user_mapped_to_uid_zero_fails(downloads):
    registry = Registry("toor", [{"etc/passwd": PASSWD + b"toor:x:0:0::/:/bin/sh\n"}])
    downloads.update(registry.blobs)
    assert enrich_and_check(registry, task(image_ref(registry.digest)))[1][0] == "FAIL"


def test_upper_layer_passwd_overrides_lower_layer(downloads):
    upper = b"app:x:0:0::/:/bin/sh\n"
    registry = Registry("app", [{"etc/passwd": b"app:x:1000:1000::/:/bin/sh\n"}, {"etc/passwd": upper}])
    downloads.update(registry.blobs)
    assert enrich_and_check(registry, task(image_ref(registry.digest)))[1][0] == "FAIL"


def test_mutable_tag_reference_stays_unknown_without_reads(downloads):
    registry = Registry("1000", [{"app/server.js": b"run()"}])
    tagged = f"{REGISTRY}.dkr.ecr.{REGION}.amazonaws.com/{REPO}:latest"
    enriched, (status, evidence) = enrich_and_check(registry, task(tagged))
    assert status == "UNKNOWN" and evidence["inherited_image_users"] == ["app"]
    assert evidence["image_user_unresolved"] == {"app": "mutable_image_reference"}
    assert registry.calls == []


@pytest.mark.parametrize("task_user,image_user,expected", [("0", "1000", "FAIL"), ("1000", "", "PASS"),
                                                           ("appuser", "1000", "UNKNOWN")])
def test_task_definition_user_keeps_precedence(downloads, task_user, image_user, expected):
    registry = Registry(image_user, [{"app/server.js": b"run()"}])
    downloads.update(registry.blobs)
    _, (status, evidence) = enrich_and_check(registry, task(image_ref(registry.digest), user=task_user))
    assert status == expected
    assert evidence["user_sources"]["app"] == {"source": "task_definition", "user": task_user}
    assert registry.calls == []


def test_image_reads_follow_the_ecr_content_opt_in(downloads):
    registry = Registry("1000", [{"app/server.js": b"run()"}])
    downloads.update(registry.blobs)
    enriched, (status, _) = enrich_and_check(registry, task(image_ref(registry.digest)), Requests(enabled=False))
    assert status == "UNKNOWN" and "ImageUsers" not in enriched and registry.calls == []


def test_image_record_for_another_image_is_not_used():
    digest = "sha256:" + "a" * 64
    item = task(image_ref("sha256:" + "b" * 64))
    item["ImageUsers"] = {"collection_status": "collected", "containers": {"app": {
        "status": "collected", "image": image_ref(digest), "image_digest": digest, "user": "1000"}}}
    assert check().evaluate(item, {})[0] == "UNKNOWN"
