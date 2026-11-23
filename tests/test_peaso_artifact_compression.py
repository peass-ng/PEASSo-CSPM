"""Lossless hosted artifact compression retains tenant and download boundaries."""
import gzip
from io import BytesIO
import json

import pytest

from peaso.storage.artifacts import S3Artifacts


class MemoryS3:
    def __init__(self):
        self.objects = {}
        self.last_presign = None

    def put_object(self, **request):
        self.objects[request["Key"]] = request

    def get_object(self, Bucket, Key):
        stored = self.objects[Key]
        return {"Body": BytesIO(stored["Body"]), "ContentEncoding": stored.get("ContentEncoding")}

    def head_object(self, Bucket, Key):
        stored = self.objects[Key]
        return {"ContentLength": len(stored["Body"]), "ContentEncoding": stored.get("ContentEncoding"),
                "Metadata": stored.get("Metadata", {})}

    def generate_presigned_url(self, operation, Params, ExpiresIn):
        self.last_presign = (operation, Params, ExpiresIn)
        return f"https://fixture.invalid/{Params['Key']}?expiry={ExpiresIn}"


@pytest.mark.parametrize("extension", ["json", "md"])
def test_hosted_report_filename_presign_keeps_owner_and_download_boundaries(extension):
    client = MemoryS3()
    artifacts = S3Artifacts("private", client=client)
    scan_id = "a" * 32
    reference = artifacts.put("owner", scan_id, "report", {"findings": []})
    filename = f"hacktricks-cspm-{scan_id}.{extension}"
    assert "expiry=300" in artifacts.presign("owner", reference, filename)
    operation, params, expiry = client.last_presign
    assert operation == "get_object" and expiry == 300
    assert params["Key"] == "artifacts/" + reference
    assert params["ResponseContentDisposition"] == f'attachment; filename="{filename}"'
    with pytest.raises(ValueError, match="Invalid artifact reference"):
        artifacts.presign("other", reference, filename)


@pytest.mark.parametrize("filename", [
    "../hacktricks-cspm-" + "a" * 32 + ".json",
    "hacktricks-cspm-" + "a" * 32 + ".json\r\nX-Injected: yes",
    "hacktricks-cspm-" + "a" * 32 + ".txt",
    "hacktricks-cspm-" + "a" * 31 + "Z.json",
])
def test_hosted_report_filename_rejects_unsafe_values(filename):
    client = MemoryS3()
    artifacts = S3Artifacts("private", client=client)
    reference = artifacts.put("owner", "a" * 32, "report", {"findings": []})
    with pytest.raises(ValueError, match="Invalid download filename"):
        artifacts.presign("owner", reference, filename)
    assert client.last_presign is None


def test_large_unicode_report_is_lossless_smaller_and_private():
    client = MemoryS3()
    artifacts = S3Artifacts("private", client=client, kms_key="fixture-key")
    value = {"findings": [{"id": str(i), "status": "UNKNOWN", "evidence": {"reason": "metadata unavailable · 数据"}} for i in range(2000)]}
    reference = artifacts.put("owner", "a" * 32, "report", value)
    obj = client.objects["artifacts/" + reference]
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    assert obj["ContentEncoding"] == "gzip" and obj["ContentType"] == "application/json"
    assert obj["ServerSideEncryption"] == "aws:kms" and obj["SSEKMSKeyId"] == "fixture-key"
    assert len(obj["Body"]) < len(encoded) / 5
    assert gzip.decompress(obj["Body"]) == encoded
    assert artifacts.get("owner", reference) == value
    assert artifacts.size("owner", reference) == len(encoded)
    assert "expiry=300" in artifacts.presign("owner", reference, "peaso-" + "a" * 32 + ".json")
    with pytest.raises(ValueError):
        artifacts.get("other", reference)
    with pytest.raises(ValueError):
        artifacts.presign("other", reference)


def test_markdown_compression_preserves_full_report_and_default_encryption():
    client = MemoryS3()
    artifacts = S3Artifacts("private", client=client)
    text = "# Full report\n\nUNKNOWN · review missing evidence\n" * 4000
    reference = artifacts.put_text("owner", "b" * 32, "markdown", text)
    obj = client.objects["artifacts/" + reference]
    assert obj["ContentEncoding"] == "gzip" and obj["ServerSideEncryption"] == "AES256"
    assert obj["ContentType"] == "text/markdown"
    assert artifacts.get_text("owner", reference) == text


def test_small_and_legacy_uncompressed_objects_remain_readable():
    client = MemoryS3()
    artifacts = S3Artifacts("private", client=client)
    reference = artifacts.put("owner", "c" * 32, "snapshot", {"schema_version": "1.0"})
    obj = client.objects["artifacts/" + reference]
    assert "ContentEncoding" not in obj
    assert artifacts.get("owner", reference) == {"schema_version": "1.0"}
    assert artifacts.size("owner", reference) == len(obj["Body"])


def test_missing_compressed_size_metadata_cannot_bypass_inline_limit():
    client = MemoryS3()
    artifacts = S3Artifacts("private", client=client)
    reference = artifacts.put("owner", "d" * 32, "report", {"data": "repeated metadata " * 10000})
    client.objects["artifacts/" + reference].pop("Metadata")
    assert artifacts.size("owner", reference) > 4 * 1024 * 1024
    assert artifacts.get("owner", reference)["data"].startswith("repeated metadata")


def test_hosted_large_pdf_download_is_private_and_keeps_its_content_type():
    client = MemoryS3()
    artifacts = S3Artifacts("private", client=client, kms_key="fixture-key")
    scan_id = "a" * 32
    body = b"%PDF-1.4\n" + b"example report object\n" * 200000
    reference = artifacts.put_pdf("owner", scan_id, body)
    obj = client.objects["artifacts/" + reference]
    assert obj["ContentType"] == "application/pdf"
    assert obj["SSEKMSKeyId"] == "fixture-key"
    assert gzip.decompress(obj["Body"]) == body
    filename = f"peasso-cspm-{scan_id}.pdf"
    assert "expiry=300" in artifacts.presign("owner", reference, filename)
    params = client.last_presign[1]
    assert params["ResponseContentDisposition"] == f'attachment; filename="{filename}"'
    assert params["ResponseCacheControl"] == "private, no-store"
    with pytest.raises(ValueError, match="Invalid artifact reference"):
        artifacts.presign("other", reference, filename)
