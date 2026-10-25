"""Saved-plan and backend guards, without AWS credentials or provider processes."""
import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import warnings
import zipfile
import pytest

spec = importlib.util.spec_from_file_location("peaso_deploy_guards", Path(__file__).parents[1] / "scripts/peaso_deploy.py")
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


def test_current_freeze_uses_its_own_byte_budget_and_rejects_one_byte_over(tmp_path, monkeypatch):
    # Match the deploy entrypoint's import path even when another CLI test has
    # added scripts/ to sys.path. Patching a second module instance would run
    # the real optimizer and legitimately shrink the archive under this cap.
    try:
        import peaso_source_archive
    except ModuleNotFoundError:
        from scripts import peaso_source_archive

    authored = tmp_path / "authored"
    authored.mkdir()
    (authored / "README.md").write_text("Reproducible corresponding source.\n")
    build = tmp_path / "build"
    monkeypatch.setattr(deploy, "ROOT", authored)
    monkeypatch.setattr(deploy, "BUILD", build)
    # Historic approvals keep their own cap; they must not govern a new freeze.
    assert deploy.artifact_update.MAX_SOURCE_ARCHIVE_BYTES == 32_000_000
    monkeypatch.setattr(deploy.artifact_update, "MAX_SOURCE_ARCHIVE_BYTES", 1)
    release = deploy.freeze_release()
    archive = build / f"peaso-source-{release['source_version']}.zip"
    measured = archive.stat().st_size
    monkeypatch.setattr(deploy, "CURRENT_SOURCE_ARCHIVE_LIMIT", measured)
    assert deploy.freeze_release() == release
    assert archive.stat().st_size == measured
    # A valid but incompressible archive still has to fail when one byte over.
    with patch.object(peaso_source_archive, "optimize_source_archive", return_value={}) as optimizer:
        monkeypatch.setattr(deploy, "CURRENT_SOURCE_ARCHIVE_LIMIT", measured - 1)
        with pytest.raises(RuntimeError, match="current archive byte limit"):
            deploy.freeze_release()
        optimizer.assert_called_once()



def test_api_archive_enforces_aws_upload_byte_limit(tmp_path, monkeypatch):
    from scripts import peaso_api_service_model_gate
    try:
        import peaso_source_archive
    except ModuleNotFoundError:
        from scripts import peaso_source_archive
    # This fixture replaces pip with a tiny dependency tree; SDK model closure
    # has separate real-botocore coverage in test_peaso_api_credential_models.
    monkeypatch.setattr(peaso_api_service_model_gate, 'prune_api_service_models',
                        lambda target: {'allowed_services': [], 'removed_models': 0})
    authored = tmp_path / "authored"
    authored.mkdir()
    GeneratedPackagePermissions().fixture_source(authored)
    build = tmp_path / "build"
    monkeypatch.setattr(deploy, "ROOT", authored)
    monkeypatch.setattr(deploy, "BUILD", build)
    monkeypatch.setattr(deploy, "run", lambda *args, **kwargs: None)
    deploy.freeze_release()
    package = deploy.package_api()
    measured = package.stat().st_size
    monkeypatch.setattr(deploy, "CURRENT_API_ARCHIVE_LIMIT", measured)
    deploy.package_api()
    monkeypatch.setattr(deploy, "CURRENT_API_ARCHIVE_LIMIT", measured - 1)
    # Successful recompression is allowed to bring a package below the limit;
    # this case verifies refusal when optimization cannot recover that byte.
    with patch.object(peaso_source_archive, 'optimize_source_archive', return_value={}) as optimizer:
        with pytest.raises(RuntimeError, match="API archive byte limit exceeded"):
            deploy.package_api()
        optimizer.assert_called_once()

def test_customer_role_quick_create_template_is_dedicated_and_narrowly_public():
    from peaso.server.validation import CUSTOMER_ROLE_TEMPLATE_URL, COLLECTOR_ROLE_ARN
    from urllib.parse import urlparse
    root = Path(__file__).parents[1]
    template_sha256 = hashlib.sha256((root / "infra/aws/customer-role.json").read_bytes()).hexdigest()
    url = urlparse(f"https://hacktricks-cspm-templates-111122223333.s3.us-east-1.amazonaws.com/customer-role-{template_sha256}.json")
    assert url.scheme == "https"
    assert url.netloc == "hacktricks-cspm-templates-111122223333.s3.us-east-1.amazonaws.com"
    assert url.path == f"/customer-role-{template_sha256}.json"
    assert CUSTOMER_ROLE_TEMPLATE_URL == "https://cspm.hacktricks.wiki/aws/customer-role.json"
    template = json.loads((root / "infra/aws/customer-role.json").read_text())
    trust = template["Resources"]["AuditRole"]["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]
    assert trust["Principal"]["AWS"] == {"Ref": "CollectorRoleArn"}
    assert "Default" not in template["Parameters"]["CollectorRoleArn"]
    assert trust["Condition"]["StringEquals"]["sts:ExternalId"] == {"Ref": "ExternalId"}
    storage = (root / "infra/aws/storage.tf").read_text()
    assert deploy.API_DELIVERY_SOURCE["storage.tf"][2] == hashlib.sha256(storage.encode()).hexdigest()
    predecessor = storage.encode()
    for after, before in deploy.API_DELIVERY_CONTENT_REVERSE["storage.tf"]:
        assert predecessor.count(after) == 1
        predecessor = predecessor.replace(after, before, 1)
    assert hashlib.sha256(predecessor).hexdigest() == deploy.API_DELIVERY_SOURCE["storage.tf"][1]
    assert 'resource "aws_s3_bucket" "templates"' in storage
    assert 'count  = var.enable_public_customer_role_template ? 1 : 0' in storage
    assert 'bucket = "${local.name}-templates-${local.account_id}"' in storage
    current_archive = root / f"infra/aws/customer-role-{template_sha256}.json"
    assert current_archive.read_bytes() == (root / "infra/aws/customer-role.json").read_bytes()
    assert 'customer_role_template_sources = merge(' in storage
    assert 'var.archived_customer_role_templates' in storage
    assert 'for_each            = var.enable_public_customer_role_template ? local.customer_role_template_sources : {}' in storage
    assert 'key                 = "customer-role-${each.key}.json"' in storage
    assert 'customer_role_template_sha256 = filesha256("${path.module}/customer-role.json")' in storage
    assert 'ignore_changes = [source]' in storage
    assert 'condition     = filesha256(each.value) == each.key' in storage
    assert 'versioning_configuration { status = "Enabled" }' in storage
    assert 'cache_control       = "public,max-age=31536000,immutable"' in storage
    assert 'metadata            = { sha256 = each.key }' in storage
    assert 'key                 = "aws/customer-role.json"' in storage
    assert 'Resource = aws_s3_object.customer_role_template[local.customer_role_template_sha256].arn' in storage
    assert 'Resource = [for object in aws_s3_object.customer_role_template' not in storage
    assert 'Action = "s3:GetObject"' in storage
    assert 'bucket              = aws_s3_bucket.frontend.id' in storage.split('resource "aws_s3_object" "customer_role_download"', 1)[1].split('resource ', 1)[0]
    assert 'bucket              = aws_s3_bucket.templates[0].id' in storage.split('resource "aws_s3_object" "customer_role_template"', 1)[1].split('resource ', 1)[0]
    assert {"aws_s3_bucket.templates", "aws_s3_bucket_policy.templates", "aws_s3_object.customer_role_template", "aws_s3_object.customer_role_download", "aws_s3_bucket_versioning.templates"} <= deploy.ALLOWED_RESOURCES
    command = deploy.frontend_sync_command(Path("/frozen/frontend"), "hacktricks-cspm-frontend-111122223333")
    excludes = [command[index + 1] for index, token in enumerate(command[:-1]) if token == "--exclude"]
    assert "--delete" in command and excludes == ["source/*", "aws/customer-role.json"]
    assert "cloudformation:ListStacks" in [action for resource in template["Resources"].values()
        if resource["Type"] == "AWS::IAM::ManagedPolicy"
        for statement in resource["Properties"]["PolicyDocument"]["Statement"]
        for action in (statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]])]


def test_customer_trust_role_cannot_read_platform_or_assume_platform_roles():
    iam = (Path(__file__).parents[1] / "infra/aws/iam.tf").read_text()
    collector = iam.split('resource "aws_iam_role_policy" "collector"', 1)[1].split('resource "aws_iam_role" "customer_trust"', 1)[0]
    broker = iam.split('resource "aws_iam_role_policy" "customer_trust"', 1)[1].split('resource "aws_iam_role" "analyzer"', 1)[0]
    assert 'Resource = local.customer_trust_arn' in collector
    assert 'Resource = "arn:aws:iam::*:role/*"' not in collector
    assert 'name        = "HackTricks-CSPM"' in iam
    assert 'Sid = "AssumeCustomerRoles", Effect = "Allow", Action = "sts:AssumeRole", Resource = "*"' in broker
    assert 'var.account_id' in broker and 'var.platform_account_ids' in broker
    assert 'Sid = "BlockLocalAndOtherActions", Effect = "Deny", NotAction = "sts:AssumeRole", Resource = "*"' in broker
    assert 'secretsmanager:' not in broker and 'dynamodb:' not in broker and 's3:' not in broker
    assert '{ Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.connectors.arn }' in collector
    assert '{ Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = [aws_secretsmanager_secret.credentials.arn] }' in collector
    assert '{ Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = var.gcp_platform_sa_secret_arn }' in collector


class GeneratedPackagePermissions(unittest.TestCase):
    def fixture_source(self, root):
        files = {
            "peaso/__init__.py": b"# offline fixture\n",
            "peaso/privesc/__init__.py": b"# supplied package\n",
            "peaso/privesc/catalog/aws/_excluded.yaml": b"techniques: []\n",
            "peaso/entrypoint.sh": b"#!/bin/sh\nexit 0\n",
            "risk_rules/reviewed-permission-supplement.json": b"{}\n",
            "bluepeass/__init__.py": b"# fixture\n",
            "bluepeass/k8s.py": b"# fixture\n",
            "bluepeass/k8s_risks.py": b"# fixture\n",
            "scripts/cloud_permission_risks.py": b"# fixture\n",
            "LICENSE": b"fixture license\n", "README.md": b"fixture readme\n",
            "pyproject.toml": b"# fixture\n",
            "Dockerfile.peaso": b"# offline compose fixture\n",
            "infra/aws/sdk-constraints.txt": b"boto3==1.43.38\nbotocore==1.43.38\ns3transfer==0.19.0\n",
        }
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o700 if name.endswith(".sh") else 0o600)
        return files

    def build_under_umask(self, root, build, mask, helper=None):
        # Only this isolated child changes its umask; pip and network are prohibited.
        code = r'''
import contextlib, importlib.util, io, json, os, socket, sys
from pathlib import Path
from unittest.mock import patch
os.umask(int(sys.argv[4], 8))
spec = importlib.util.spec_from_file_location("offline_deploy", sys.argv[1])
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)
deploy.ROOT, deploy.BUILD = Path(sys.argv[2]), Path(sys.argv[3])
def offline_pip(args, **kwargs):
    assert args[1:4] == ["-m", "pip", "install"], args
    assert "--no-compile" in args  # Do not ship bytecode for the build host interpreter.
    constraint = Path(args[args.index("--constraint") + 1])
    assert constraint == deploy.BUILD / "source-snapshot/infra/aws/sdk-constraints.txt"
    assert constraint.read_bytes() == b"boto3==1.43.38\nbotocore==1.43.38\ns3transfer==0.19.0\n"
    target = Path(args[args.index("--target") + 1])
    for name, content, executable in [("dependency/__init__.py", b"# dependency\n", False),
                                       ("dependency/lib.so", b"fixture shared library", False),
                                       ("bin/required-tool", b"#!/bin/sh\nexit 0\n", True)]:
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        if executable:
            path.chmod(0o700)
deploy.run = offline_pip
# The fixture dependency has no SDK. Keep permission and byte-identity tests
# independent of the separately tested real SDK model source inventory.
from scripts import peaso_api_service_model_gate
peaso_api_service_model_gate.prune_api_service_models = lambda target: {'allowed_services': [], 'removed_models': 0}
with patch.object(socket, "socket", side_effect=AssertionError("No network in fixture")), contextlib.redirect_stdout(io.StringIO()):
    release = deploy.freeze_release()
    deploy.package_api()
    deploy.verify_api_source()
print(json.dumps(release))
'''
        result = subprocess.run([sys.executable, "-c", code,
                                 str(helper or Path(deploy.__file__).resolve()), str(root), str(build), oct(mask)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def assert_public_tree(self, tree):
        for path in [tree, *tree.rglob("*")]:
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode, 0o755 if path.is_dir() or mode & 0o111 else 0o644, str(path))
            # UID10001 has no ownership/group assumption: require other-user access.
            self.assertTrue(mode & 0o004, str(path))
            if path.is_dir():
                self.assertTrue(mode & 0o001, str(path))
        # Enter through an inherited directory descriptor, like mounting the public
        # tree independently of its deliberately private enclosing cache directory.
        code = r'''
import hashlib, json, os, sys
from pathlib import Path
os.fchdir(int(sys.argv[1]))
if os.geteuid() == 0:
    os.setgroups([])
    os.setgid(10001)
    os.setuid(10001)
assert os.geteuid() != 0
files = {p.as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(".").rglob("*") if p.is_file()}
print(json.dumps(files, sort_keys=True))
'''
        descriptor = os.open(tree, os.O_RDONLY | os.O_DIRECTORY)
        try:
            result = subprocess.run([sys.executable, "-c", code, str(descriptor)], pass_fds=(descriptor,),
                                    capture_output=True, text=True, timeout=10)
        finally:
            os.close(descriptor)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = {p.relative_to(tree).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in tree.rglob("*") if p.is_file()}
        self.assertEqual(json.loads(result.stdout), expected)

    def test_normal_helper_output_portable_and_deterministic_across_umasks(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve() / "authored"
            root.mkdir(mode=0o700)
            files = self.fixture_source(root)
            originals = {p: (p.read_bytes() if p.is_file() else None, stat.S_IMODE(p.stat().st_mode))
                         for p in [root, *root.rglob("*")]}
            private = root.parent / "private-cache"
            private.mkdir(mode=0o700)
            builds = [private / "restrictive", private / "ordinary"]
            releases, archives = [], []
            for mask, build in zip((0o077, 0o022), builds):
                build.mkdir(mode=0o700)
                for name in ("release.json", "api.zip"):
                    (build / name).write_bytes(b"")
                    (build / name).chmod(0o600)
                release = self.build_under_umask(root, build, mask)
                releases.append(release)
                self.assert_public_tree(build / "source-snapshot")
                self.assert_public_tree(build / "api-package")
                self.assertEqual(stat.S_IMODE((build / "source-snapshot/peaso/entrypoint.sh").stat().st_mode), 0o755)
                for name, content in files.items():
                    self.assertEqual((build / "source-snapshot" / name).read_bytes(), content)
                    self.assertEqual(release["files"][name], hashlib.sha256(content).hexdigest())
                for name in ("release.json", "api.zip"):
                    self.assertEqual(stat.S_IMODE((build / name).stat().st_mode), 0o600)
                source_zip = build / f"peaso-source-{release['source_version']}.zip"
                self.assertEqual(stat.S_IMODE(source_zip.stat().st_mode), 0o666 & ~mask)
                # Reconstruct the historical source serializer independently: no source ZIP format drift.
                expected_source = io.BytesIO()
                with zipfile.ZipFile(expected_source, "w", zipfile.ZIP_DEFLATED) as archive:
                    for name, content in [*sorted(files.items()), ("release.json", json.dumps(release, indent=2).encode())]:
                        info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                        info.compress_type = zipfile.ZIP_DEFLATED
                        info.external_attr = 0o644 << 16
                        archive.writestr(info, content)
                self.assertEqual(source_zip.read_bytes(), expected_source.getvalue())
                archives.append((source_zip.read_bytes(), (build / "api.zip").read_bytes()))
                with zipfile.ZipFile(build / "api.zip") as archive:
                    extracted = build / "extracted-api"
                    extracted.mkdir(mode=0o755)
                    for info in archive.infolist():
                        expected = 0o755 if info.filename in {"bin/required-tool", "peaso/entrypoint.sh"} else 0o644
                        self.assertEqual(stat.S_IMODE(info.external_attr >> 16), expected, info.filename)
                        self.assertEqual(info.create_system, 3)
                        self.assertEqual(archive.read(info), (build / "api-package" / info.filename).read_bytes())
                        path = extracted / info.filename
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(archive.read(info))
                        path.chmod(stat.S_IMODE(info.external_attr >> 16))
                    for directory in [extracted, *(p for p in extracted.rglob("*") if p.is_dir())]:
                        directory.chmod(0o755)
                    self.assert_public_tree(extracted)
                self.assertEqual(stat.S_IMODE(build.stat().st_mode), 0o700)
            self.assertEqual(releases[0], releases[1])
            self.assertEqual(archives[0], archives[1])
            # Replacing existing private artifacts under a more permissive caller
            # must retain their enclosing and archive filesystem permissions.
            release = self.build_under_umask(root, builds[0], 0o022)
            self.assertEqual(release, releases[0])
            for name in ("release.json", "api.zip", f"peaso-source-{release['source_version']}.zip"):
                self.assertEqual(stat.S_IMODE((builds[0] / name).stat().st_mode), 0o600)
            self.assertEqual((builds[0] / "api.zip").read_bytes(), archives[0][1])
            self.assertEqual(stat.S_IMODE(builds[0].stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
            for path, (content, mode) in originals.items():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode, str(path))
                if content is not None:
                    self.assertEqual(path.read_bytes(), content)

    def frozen_fixture(self, folder):
        root = Path(folder).resolve() / "authored"
        root.mkdir()
        self.fixture_source(root)
        build = root.parent / "private-build"
        build.mkdir(mode=0o700)
        with patch.object(deploy, "ROOT", root), patch.object(deploy, "BUILD", build), \
                contextlib.redirect_stdout(io.StringIO()):
            release = deploy.freeze_release()
        return root, build, release

    def test_worker_smoke_mount_readable_under077_without_private_manifest_chmod(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve() / "authored"
            root.mkdir()
            self.fixture_source(root)
            build = root.parent / "private-build"
            build.mkdir(mode=0o700)
            self.build_under_umask(root, build, 0o077)
            private_manifest = build / "release.json"
            public_manifest = build / "source-snapshot/release.json"
            before = private_manifest.read_bytes()
            with patch.object(deploy, "ROOT", root), patch.object(deploy, "BUILD", build), \
                    patch.object(deploy, "run") as commands:
                deploy.build_worker("offline-fixture")
            self.assertEqual(commands.call_count, 2)
            build_command, smoke_command = [call.args[0] for call in commands.call_args_list]
            self.assertEqual(build_command[:2], ["docker", "build"])
            self.assertEqual(smoke_command[:2], ["docker", "run"])
            self.assertEqual(smoke_command[smoke_command.index("-v") + 1], f"{public_manifest}:/release.json:ro")
            self.assertIn("--read-only", smoke_command)
            self.assertEqual(smoke_command[smoke_command.index("--network") + 1], "none")
            self.assertEqual(public_manifest.read_bytes(), before)
            self.assertEqual(private_manifest.read_bytes(), before)
            self.assertEqual(stat.S_IMODE(private_manifest.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(public_manifest.stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(build.stat().st_mode), 0o700)
            self.assert_public_tree(build / "source-snapshot")

    def test_frontend_npm_links_under077_preserve_frozen_guards_and_refreeze(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve() / "authored"
            root.mkdir()
            self.fixture_source(root)
            frontend = root / "frontend/src/main.tsx"
            frontend.parent.mkdir(parents=True)
            frontend.write_bytes(b"// declared frontend source\n")
            frontend.chmod(0o600)
            build = root.parent / "private-build"
            build.mkdir(mode=0o700)
            code = r'''
import contextlib, importlib.util, io, json, os, socket, stat, sys
from pathlib import Path
from unittest.mock import patch
os.umask(0o077)
spec = importlib.util.spec_from_file_location("lifecycle_deploy", sys.argv[1])
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)
deploy.ROOT, deploy.BUILD = Path(sys.argv[2]), Path(sys.argv[3])
root, build = deploy.ROOT, deploy.BUILD
originals = {p: (p.read_bytes() if p.is_file() else None, stat.S_IMODE(p.stat().st_mode))
             for p in [root, *root.rglob("*")]}
def rejected(call, message):
    try:
        call()
    except RuntimeError as error:
        assert message in str(error), str(error)
    else:
        raise AssertionError("Declared source guard did not reject mutation")
with patch.object(socket, "socket", side_effect=AssertionError("No network")), contextlib.redirect_stdout(io.StringIO()):
    release = deploy.freeze_release()
    snapshot = build / "source-snapshot"
    archive = build / ("peaso-source-" + release["source_version"] + ".zip")
    archive_before = archive.read_bytes()
    outside = root.parent / "owned-npm-fixture"
    outside.mkdir()
    binary = outside / "esbuild"
    binary.write_bytes(b"owned npm binary fixture")
    binary.chmod(0o700)
    private = outside / "private-state"
    private.write_bytes(b"outside state must remain unchanged")
    source_copy = outside / "source-copy.py"
    source_copy.write_bytes((snapshot / "peaso/privesc/__init__.py").read_bytes())
    outside_before = {p: (p.read_bytes() if p.is_file() else None, stat.S_IMODE(p.stat().st_mode))
                      for p in [outside, *outside.rglob("*")]}
    modules = snapshot / "frontend/node_modules"
    installed = modules / "@esbuild/linux-x64/bin/esbuild"
    installed.parent.mkdir(parents=True)
    os.link(binary, installed)
    tool = modules / "esbuild/bin/esbuild"
    tool.parent.mkdir(parents=True)
    os.link(installed, tool)
    bins = modules / ".bin"
    bins.mkdir()
    for index in range(15):
        (bins / ("tool-" + str(index))).symlink_to("../esbuild/bin/esbuild")
    (modules / "linked-vendor").symlink_to(outside, target_is_directory=True)
    dist = snapshot / "frontend/dist"
    dist.mkdir()
    (dist / "index.html").write_bytes(b"generated frontend")
    (dist / "linked-asset").symlink_to(private)
    generated_before = {p: (p.lstat().st_mode, os.readlink(p) if p.is_symlink() else None)
                        for p in [modules, dist, *modules.rglob("*"), *dist.rglob("*")]}
    deploy.normalize_frozen_permissions(snapshot, ["release.json", *release["files"]])
    assert deploy.source_root() == snapshot
    with patch.object(deploy, "run") as commands:
        deploy.build_worker("offline-lifecycle")
    assert commands.call_count == 2
    smoke = commands.call_args_list[1].args[0]
    assert smoke[:2] == ["docker", "run"]
    assert smoke[smoke.index("-v") + 1] == str(snapshot / "release.json") + ":/release.json:ro"
    for p, (mode, target) in generated_before.items():
        assert p.lstat().st_mode == mode, p
        if target is not None:
            assert os.readlink(p) == target, p
    # Manifest-declared runtime files and selected frontend ancestor paths
    # retain strict content, link, and mode guards despite ignored npm outputs.
    runtime = snapshot / "peaso/privesc/__init__.py"
    content = runtime.read_bytes()
    runtime.write_bytes(b"# tampered declared runtime\n")
    rejected(deploy.source_root, "Frozen source changed")
    runtime.write_bytes(content)
    runtime.unlink()
    runtime.symlink_to(source_copy)
    rejected(deploy.source_root, "symlinks or external")
    runtime.unlink()
    os.link(source_copy, runtime)
    rejected(deploy.source_root, "owned and unlinked")
    runtime.unlink()
    runtime.write_bytes(content)
    runtime.chmod(0o644)
    selected = snapshot / "frontend/src"
    saved = selected.with_name("saved-src")
    selected.rename(saved)
    selected.symlink_to(outside, target_is_directory=True)
    rejected(deploy.source_root, "symlinks or external")
    selected.unlink()
    saved.rename(selected)
    runtime.chmod(0o600)
    rejected(deploy.source_root, "nonportable")
    runtime.chmod(0o644)
    assert deploy.source_root() == snapshot
    assert deploy.freeze_release() == release
    assert archive.read_bytes() == archive_before
    assert not modules.exists() and not dist.exists()
    assert deploy.source_root() == snapshot
    for p, (content, mode) in {**originals, **outside_before}.items():
        assert stat.S_IMODE(p.stat().st_mode) == mode, p
        if content is not None:
            assert p.read_bytes() == content, p
    assert stat.S_IMODE(build.stat().st_mode) == 0o700
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    assert stat.S_IMODE((build / "release.json").stat().st_mode) == 0o600
print(json.dumps({"umask": "0077", "npm_bin_symlinks": 15, "npm_hardlinks": 2,
                  "outside_links_unchanged": True, "declared_tamper_guards": 5,
                  "source_archive_bytes_unchanged": True}))
'''
            result = subprocess.run([sys.executable, "-c", code, str(Path(deploy.__file__).resolve()), str(root), str(build)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["outside_links_unchanged"])
            self.assert_public_tree(build / "source-snapshot")

    def test_existing_generated_symlinks_rejected_before_output_mutation(self):
        for name, operation in (("source-snapshot", "freeze"), ("api-package", "package"),
                                ("api.zip", "package"), ("release.json", "freeze"),
                                ("source-archive", "freeze"), ("build", "freeze")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as folder:
                root, build, release = self.frozen_fixture(folder)
                external = root.parent / "external"
                external.mkdir(mode=0o700)
                sentinel = external / "sentinel"
                sentinel.write_bytes(b"private unchanged contents")
                sentinel.chmod(0o600)
                if name == "source-archive":
                    path = build / f"peaso-source-{release['source_version']}.zip"
                else:
                    path = build if name == "build" else build / name
                if path.is_dir():
                    # Keep the real generated tree intact; only redirect its directory entry.
                    path.rename(path.with_name(path.name + "-saved"))
                elif path.exists():
                    path.unlink()
                path.symlink_to(external if name in {"build", "source-snapshot", "api-package"} else sentinel)
                with patch.object(deploy, "ROOT", root), patch.object(deploy, "BUILD", build), \
                        patch.object(deploy, "run", side_effect=AssertionError("No pip before safety checks")), \
                        self.assertRaisesRegex(RuntimeError, "symlinks or external"):
                    deploy.freeze_release() if operation == "freeze" else deploy.package_api()
                self.assertEqual(sentinel.read_bytes(), b"private unchanged contents")
                self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(external.stat().st_mode), 0o700)

    def test_linked_public_entries_rejected_before_chmod(self):
        for link_type in ("symlink", "hardlink"):
            with self.subTest(link_type=link_type), tempfile.TemporaryDirectory() as folder:
                root, build, _ = self.frozen_fixture(folder)
                sentinel = root.parent / "private-state"
                sentinel.write_bytes(b"private state")
                sentinel.chmod(0o600)
                target = build / "api-package"
                target.mkdir(mode=0o700)
                ordinary = target / "ordinary.py"
                ordinary.write_bytes(b"# fixture\n")
                ordinary.chmod(0o600)
                link = target / "unexpected.py"
                link.symlink_to(sentinel) if link_type == "symlink" else os.link(sentinel, link)
                with patch.object(deploy, "ROOT", root), patch.object(deploy, "BUILD", build), \
                        self.assertRaisesRegex(RuntimeError, "symlinks|unlinked"):
                    deploy.normalize_public_tree(target)
                self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(ordinary.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
                self.assertEqual(sentinel.read_bytes(), b"private state")
                with patch.object(deploy, "ROOT", root), patch.object(deploy, "BUILD", build), \
                        self.assertRaisesRegex(RuntimeError, "only to generated"):
                    deploy.normalize_public_tree(root)

    def test_installer_symlink_rejected_before_source_copy_or_zip(self):
        with tempfile.TemporaryDirectory() as folder:
            root, build, _ = self.frozen_fixture(folder)
            external = root.parent / "external"
            external.mkdir(mode=0o700)
            def installer(args, **kwargs):
                target = Path(args[args.index("--target") + 1])
                (target / "bluepeass").symlink_to(external)
            with patch.object(deploy, "ROOT", root), patch.object(deploy, "BUILD", build), \
                    patch.object(deploy, "run", side_effect=installer), \
                    self.assertRaisesRegex(RuntimeError, "symlinks or external"):
                deploy.package_api()
            self.assertEqual(list(external.iterdir()), [])
            self.assertFalse((build / "api.zip").exists())
            self.assertEqual(stat.S_IMODE(external.stat().st_mode), 0o700)

    def test_source_directory_symlink_and_manifest_traversal_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root, build, release = self.frozen_fixture(folder)
            catalog = root / "peaso/privesc/catalog"
            saved = catalog.with_name("saved-catalog")
            catalog.rename(saved)
            catalog.symlink_to(saved)
            with patch.object(deploy, "ROOT", root), patch.object(deploy, "BUILD", build), \
                    self.assertRaisesRegex(RuntimeError, "symlinks or external"):
                deploy.freeze_release()
            sentinel = build / "outside.py"
            sentinel.write_bytes(b"# unchanged\n")
            sentinel.chmod(0o600)
            for unsafe in ("../outside.py", str(sentinel), "peaso/../outside.py", "peaso\\outside.py"):
                changed = dict(release, files=dict(release["files"], **{unsafe: hashlib.sha256(sentinel.read_bytes()).hexdigest()}))
                for manifest in (build / "release.json", build / "source-snapshot/release.json"):
                    manifest.write_text(json.dumps(changed))
                with self.subTest(unsafe=unsafe), patch.object(deploy, "ROOT", root), patch.object(deploy, "BUILD", build), \
                        self.assertRaisesRegex(RuntimeError, "Unsafe generated member"):
                    deploy.source_root()
            self.assertEqual(sentinel.read_bytes(), b"# unchanged\n")
            self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), 0o600)

    def test_verifier_rejects_dependency_mode_content_duplicates_and_unsafe_members(self):
        for corruption in ("member-mode", "staged-mode", "staged-directory-mode", "dependency-bytes",
                           "duplicate", "symlink-member", "unsafe-member", "extra-staged-file"):
            with self.subTest(corruption=corruption), tempfile.TemporaryDirectory() as folder:
                root = Path(folder).resolve() / "authored"
                root.mkdir()
                self.fixture_source(root)
                build = root.parent / "private-build"
                build.mkdir(mode=0o700)
                self.build_under_umask(root, build, 0o077)
                path = build / "api.zip"
                with zipfile.ZipFile(path) as archive:
                    members = [(info, archive.read(info)) for info in archive.infolist()]
                if corruption == "member-mode":
                    next(info for info, _ in members if info.filename == "dependency/__init__.py").external_attr = (stat.S_IFREG | 0o600) << 16
                elif corruption == "staged-mode":
                    (build / "api-package/dependency/__init__.py").chmod(0o600)
                elif corruption == "staged-directory-mode":
                    (build / "api-package/dependency").chmod(0o700)
                elif corruption == "dependency-bytes":
                    (build / "api-package/dependency/__init__.py").write_bytes(b"# changed dependency\n")
                elif corruption == "duplicate":
                    members.append(members[0])
                elif corruption in {"symlink-member", "unsafe-member"}:
                    info = zipfile.ZipInfo("dependency/link" if corruption == "symlink-member" else "../outside.py")
                    info.external_attr = ((stat.S_IFLNK | 0o777) if corruption == "symlink-member" else (stat.S_IFREG | 0o644)) << 16
                    members.append((info, b"outside target"))
                else:
                    extra = build / "api-package/unarchived.py"
                    extra.write_bytes(b"# extra staged code\n")
                    extra.chmod(0o644)
                with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
                    for info, content in members:
                        # Suppress only zipfile's expected duplicate-write warning.
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", message="Duplicate name:", category=UserWarning)
                            archive.writestr(info, content)
                with patch.object(deploy, "ROOT", root), patch.object(deploy, "BUILD", build), \
                        self.assertRaisesRegex(RuntimeError, "nonportable|differ|duplicate|Unsafe"):
                    deploy.verify_api_source()


class DeploymentGuards(unittest.TestCase):
    def summary(self, actions, before=None, name="worker", resource_type="aws_ecr_repository"):
        with tempfile.TemporaryDirectory() as folder:
            plan = Path(folder) / "review.tfplan"
            plan.write_bytes(b"reviewed fixture plan")
            change = {"address": f"{resource_type}.{name}", "mode": "managed", "type": resource_type,
                      "name": name, "change": {"actions": actions, "before": before,
                                               "after": {"name": "hacktricks-cspm-worker"}}}
            response = SimpleNamespace(stdout=json.dumps({"resource_changes": [change]}))
            with patch.object(deploy, "terraform", return_value=response), contextlib.redirect_stdout(io.StringIO()):
                deploy.plan_summary(plan)
            return json.loads(plan.with_suffix(".review.json").read_text())

    def test_create_only_counts(self):
        self.assertEqual(self.summary(["create"])["counts"], {"create": 1, "update": 0, "delete": 0})

    def test_existing_updates_refused(self):
        with self.assertRaisesRegex(RuntimeError, "Non-additive"):
            self.summary(["update"], {"name": "hacktricks-cspm-worker"})

    def test_deletions_and_replacements_refused(self):
        for actions in (["delete"], ["delete", "create"], ["create", "delete"]):
            with self.subTest(actions=actions), self.assertRaisesRegex(RuntimeError, "Destructive"):
                self.summary(actions)

    def test_create_with_existing_before_refused(self):
        with self.assertRaisesRegex(RuntimeError, "Non-additive"):
            self.summary(["create"], {"id": "existing"})

    def test_unrelated_resource_refused(self):
        with self.assertRaisesRegex(RuntimeError, "outside"):
            self.summary(["create"], name="tools")

    def test_backend_guard(self):
        expected = {"bucket": "example-deployment-state", "key": "cspm/terraform.tfstate",
                    "region": "us-east-1", "encrypt": True, "use_lockfile": True}
        with tempfile.TemporaryDirectory() as folder, patch.object(deploy, "INFRA", Path(folder)), \
                patch.object(deploy.deployment, "backend", return_value=expected), \
                patch.object(deploy, "ACCOUNT", "111122223333"):
            metadata = Path(folder) / ".terraform/terraform.tfstate"
            metadata.parent.mkdir()
            metadata.write_text(json.dumps({"backend": {"type": "s3", "config": expected}}))
            deploy.verify_backend()
            for key, value in (("key", "wiki/terraform.tfstate"), ("encrypt", False), ("use_lockfile", False), ("bucket", "other")):
                metadata.write_text(json.dumps({"backend": {"type": "s3", "config": dict(expected, **{key: value})}}))
                with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, "backend"):
                    deploy.verify_backend()

    def test_alternate_export_refused_before_writes(self):
        with tempfile.TemporaryDirectory() as folder, self.assertRaisesRegex(RuntimeError, "complete current"):
            deploy.freeze_release(Path(folder))

    def test_corresponding_source_includes_exact_permission_sync_inputs(self):
        required = {
            "scripts/sync_hacktricks_permissions.py", "scripts/fetch_hacktricks_permissions.py",
            ".github/workflows/sync-permission-categorizations.yml",
            "tests/test_permission_sync_supplement.py", "tests/test_canonical_permissions.py",
            "tests/test_permission_source_fetch.py", "scripts/sync_hacktricks_privesc.py",
            "scripts/export_privesc_catalog.py", "tests/test_privesc_sync.py",
            "peaso/__init__.py", "peaso/worker.py", "peaso/server/app.py",
            "peaso/checks/supplied.py", "peaso/rulepacks/reviewed.json",
            "peaso/privesc/__init__.py", "peaso/privesc/catalog/aws/supplied.yaml",
            "peaso/privesc/catalog/azure/supplied.yaml", "peaso/privesc/catalog/gcp/supplied.yaml",
            "peaso/privesc/catalog/k8s/supplied.yaml", "risk_rules/aws.yaml", "risk_rules/gcp.yaml",
            "risk_rules/hacktricks-source.json", "risk_rules/reviewed-permission-supplement.json",
            "frontend/src/main.tsx", "frontend/public/icon.svg", "frontend/tests/ui.spec.ts",
            "frontend/e2e/fixture.ts", "frontend/package.json", "frontend/package-lock.json",
            "frontend/vite.config.ts", "frontend/index.html", "infra/aws/main.tf",
            "infra/aws/Dockerfile.worker", "infra/aws/sdk-constraints.txt", "infra/aws/customer-role.json",
            "infra/aws/.terraform.lock.hcl",
            "scripts/peaso_deploy.py", "scripts/peaso_test_resources/fixture.py", "docs/peaso-aws.md",
            "tests/test_peaso_privesc.py", "bluepeass/__init__.py", "bluepeass/k8s.py",
            "bluepeass/k8s_risks.py", "scripts/cloud_permission_risks.py",
            "LICENSE", "README.md", "pyproject.toml", "Dockerfile.peaso",
            "docker-compose.yml", ".dockerignore", ".env.example",
        }
        excluded = {
            ".git/config", ".cache/receipt.json", ".peaso/private.json", ".env", ".env.production", ".venv/secret.py",
            "env/credentials.json", "private/credentials.json", "operator-note.md", "operator-note-2.md",
            "docs/operator-note.md", "scripts/unrelated_sync.py", "tests/test_unrelated_sync.py",
            ".github/workflows/unrelated.yml", ".github/workflows/.env",
            ".github/workflows/.private/sync-permission-categorizations.yml",
            "peaso/.git/config", "peaso/.cache/receipt.json", "peaso/.env",
            "peaso/.private/secret.py", "risk_rules/.credentials.json",
            "frontend/src/.hidden/secret.ts", "frontend/public/.hidden/key.json",
            "peaso/__pycache__/cached.py", "peaso/secret.key", "peaso/secret.pem",
            "peaso/cache.pyc", "peaso/local.db", "peaso/local.sqlite", "peaso/local.sqlite3",
            "peaso/output.log", "frontend/src/build.tsbuildinfo", "frontend/tests/credentials.json",
        }
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            build = root / "fixture-build"
            build.mkdir()
            for name in required | excluded:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                content = ("boto3==1.43.38\nbotocore==1.43.38\ns3transfer==0.19.0\n"
                           if name == "infra/aws/sdk-constraints.txt" else
                           "{}\n" if path.suffix == ".json" else "# offline fixture\n")
                path.write_text(content)
            with patch.object(deploy, "ROOT", root), patch.object(deploy, "BUILD", build), \
                    patch.object(deploy, "run", side_effect=AssertionError("No external commands in fixture")), \
                    contextlib.redirect_stdout(io.StringIO()):
                release = deploy.freeze_release()
                self.assertEqual(set(release["files"]), required)
                self.assertEqual(release["files"]["infra/aws/sdk-constraints.txt"],
                                 "6ff70b35da9d3f2e49c3cccaf6c0e4ff07d0a000cd4a9c6071a8ab4dd25c293c")
                archive_path = build / f"peaso-source-{release['source_version']}.zip"
                with zipfile.ZipFile(archive_path) as archive:
                    self.assertEqual(set(archive.namelist()), required | {"release.json"})
                    self.assertEqual(json.loads(archive.read("release.json")), release)
                    for name in required:
                        self.assertEqual(archive.read(name), (root / name).read_bytes())
                        self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), release["files"][name])
                    self.assertTrue(excluded.isdisjoint(archive.namelist()))
                self.assertEqual(deploy.source_root(), build / "source-snapshot")
                workflow = build / "source-snapshot/.github/workflows/sync-permission-categorizations.yml"
                workflow.write_text("# changed after freeze\n")
                with self.assertRaisesRegex(RuntimeError, "Frozen source changed"):
                    deploy.source_root()

    def test_corresponding_source_includes_public_reproduction_inputs(self):
        reproduction = {
            "docs/compliance-ledgers/README.md", "docs/compliance-ledgers/manifest.json",
            "docs/compliance-ledgers/new-checks-aws.json", "docs/compliance-ledgers/aws-cis.verify.md",
            "docs/compliance-ledgers/descriptions/aws-1.json", "docs/compliance-ledgers/descriptions/aws-1.md",
            "docs/compliance-ledgers/inputs/aws-cis.json",
            "docs/compliance-ledgers/provenance/aws_config_all_resources_recorded.superseded-8f9c88b1.json",
            "docs/compliance-ledgers/inputs/compliance-requirements-matrix.json.gz", "docs/compliance-ledgers/inputs/compliance-requirements-summary.json",
            "docs/compliance-ledgers/inputs/compliance-runtime-coverage.json",
            "tests/conftest.py", "tests/compliance_draft_isolation.py", "tests/compliance_source_conservation.py",
            "tests/aws_tag_policy_fixture.py",
            "tests/test_combined_release_gate.py", "tests/fixtures/remediation_aws_reviewed_overlay.json",
            "tests/fixtures/markdown_anchor_expected.json",
            "tests/test_next20_aws.py",
            "tests/fixtures/next20_aws.json",
            "tests/test_secret_rotation_collector.py",
            "tests/test_azure_apim_native.py",
            "tests/test_gcp_audit_native.py",
            'tests/test_post_dfaf_aws.py',
            'tests/test_post_dfaf_azure.py',
            'tests/fixtures/post_dfaf_aws.json',
            'tests/fixtures/post_dfaf_azure/cases.json',
            'tests/fixtures/post_dfaf_integration/conservation.json',
            'tests/fixtures/post_dfaf_integration/contract.json',
            'tests/fixtures/post_dfaf_integration/derived-row-preimages.json',
            "tests/fixtures/batch_remaining_gcp_k8s/central-fixture-fragment.json",
            "tests/fixtures/batch_remaining_gcp_k8s/full-id-disposition.json",
            "tests/fixtures/batch_remaining_azure_vm_storage/central-fixture-fragment.json",
            "tests/fixtures/batch_remaining_azure_vm_storage/full-id-disposition.json",
            "Blue-AWSPEAS.py", "tests/test_blue_awspeas_access_analyzer_read_only.py",
            "tests/fixtures/privesc/synthetic_aws.py", "tests/fixtures/privesc/catalog/aws/fixture.yaml",
            "scripts/__init__.py", "scripts/check_test_skips.py", "peaso/__init__.py",
            "peaso/privesc/__init__.py",
        }
        excluded = {
            "docs/compliance-ledgers/.work/swarm/draft.json", "docs/compliance-ledgers/.work/notes.md",
            "docs/compliance-ledgers/gcp-c5.verify.log", "docs/compliance-ledgers/untitled.md",
            "docs/compliance-ledgers/Untitled-2.json", "docs/compliance-ledgers/nested/unlisted.json",
            "docs/compliance-ledgers/inputs/raw.txt", "docs/compliance-ledgers/provenance/note.md",
            "docs/handoff/FINAL_GATES.md", "docs/handoff/compliance-pending-signed-proposal-queue.json",
            "docs/handoff/compliance-requirements-matrix.private.json",
            "tests/fixtures/credentials.json", "tests/fixtures/privesc/catalog/aws/extra.yaml",
            "tests/fixtures/privesc/private.yaml", "tests/unrelated_helper.py", "tests/e2e/test_unlisted.py",
            "scripts/unrelated_tool.py", "untitled-notes.md",
        }
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            build = root / "fixture-build"
            build.mkdir()
            for name in reproduction | excluded:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if path.suffix == ".gz":
                    path.write_bytes(b"\x1f\x8b offline fixture")
                else:
                    path.write_text("{}\n" if path.suffix == ".json" else "# offline fixture\n")
            fixture_name = "tests/fixtures/markdown_anchor_expected.json"
            fixture_bytes = (Path(__file__).parents[1] / fixture_name).read_bytes()
            (root / fixture_name).write_bytes(fixture_bytes)
            with patch.object(deploy, "ROOT", root), patch.object(deploy, "BUILD", build), \
                    patch.object(deploy, "run", side_effect=AssertionError("No external commands in fixture")), \
                    contextlib.redirect_stdout(io.StringIO()):
                release = deploy.freeze_release()
                self.assertEqual(set(release["files"]), reproduction)
                self.assertEqual(release["files"][fixture_name], hashlib.sha256(fixture_bytes).hexdigest())
                archive_path = build / f"peaso-source-{release['source_version']}.zip"
                with zipfile.ZipFile(archive_path) as archive:
                    self.assertEqual(set(archive.namelist()), reproduction | {"release.json"})
                    self.assertEqual(json.loads(archive.read("release.json")), release)
                    self.assertEqual(archive.read(fixture_name), fixture_bytes)
                    self.assertEqual(hashlib.sha256(archive.read(fixture_name)).hexdigest(),
                                     release["files"][fixture_name])
                    for name in reproduction:
                        self.assertEqual(archive.read(name), (root / name).read_bytes())
                self.assertEqual(deploy.source_root(), build / "source-snapshot")
                ledger = build / "source-snapshot/docs/compliance-ledgers/new-checks-aws.json"
                ledger.write_text("{\"changed\": true}\n")
                with self.assertRaisesRegex(RuntimeError, "Frozen source changed"):
                    deploy.source_root()

    def test_reproduction_ledger_symlink_and_invalid_json_refused(self):
        for case in ("symlink", "json"):
            with self.subTest(case), tempfile.TemporaryDirectory() as folder:
                root = Path(folder).resolve()
                (root / "peaso").mkdir()
                (root / "peaso/__init__.py").write_text("# offline fixture\n")
                ledger = root / "docs/compliance-ledgers/aws-cis.json"
                ledger.parent.mkdir(parents=True)
                if case == "symlink":
                    target = root / "outside.json"
                    target.write_text("{}\n")
                    ledger.symlink_to(target)
                    message = "symlinks or external"
                else:
                    ledger.write_text("{not json")
                    message = "Source JSON changing or invalid"
                build = root / "fixture-build"
                with patch.object(deploy, "ROOT", root), patch.object(deploy, "BUILD", build), \
                        self.assertRaisesRegex(RuntimeError, message):
                    deploy.freeze_release()
                self.assertFalse(build.exists())

    def test_public_sync_workflow_symlink_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            target = root / "public.yml"
            target.write_text("# fixture\n")
            workflow = root / ".github/workflows/sync-permission-categorizations.yml"
            workflow.parent.mkdir(parents=True)
            workflow.symlink_to(target)
            build = root / "fixture-build"
            with patch.object(deploy, "ROOT", root), patch.object(deploy, "BUILD", build), \
                    self.assertRaisesRegex(RuntimeError, "symlinks or external"):
                deploy.freeze_release()
            self.assertFalse(build.exists())

    def test_api_zip_and_smoke_directory_must_match_frozen_source(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(deploy, "BUILD", Path(folder)):
            root = Path(folder)
            member = "peaso/privesc/__init__.py"
            content = b"# supplied runtime source\n"
            release = {"files": {member: hashlib.sha256(content).hexdigest()}}
            for directory in (root / "source-snapshot", root / "api-package"):
                path = directory / member
                path.parent.mkdir(parents=True)
                path.write_bytes(content)
            for manifest in (root / "release.json", root / "source-snapshot/release.json"):
                manifest.write_text(json.dumps(release))
            # Match the portable public trees produced by freeze/package helpers,
            # independently of the caller's umask; leave the private parent alone.
            for directory in (root / "source-snapshot", root / "api-package"):
                for path in (directory, *directory.rglob("*")):
                    path.chmod(0o755 if path.is_dir() else 0o644)
            with zipfile.ZipFile(root / "api.zip", "w") as archive:
                info = zipfile.ZipInfo(member)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, content)
            with contextlib.redirect_stdout(io.StringIO()):
                deploy.verify_api_source()
            with zipfile.ZipFile(root / "api.zip", "w") as archive:
                archive.writestr(member, b"different source")
            with self.assertRaisesRegex(RuntimeError, "ZIP source differs"):
                deploy.verify_api_source()
            with zipfile.ZipFile(root / "api.zip", "w") as archive:
                archive.writestr("peaso/other.py", content)
            with self.assertRaisesRegex(RuntimeError, "omits supplied"):
                deploy.verify_api_source()

    def test_prospective_sizes_and_supported_overrides(self):
        deploy.verify_worker_resources({"collector": {"cpu": 1024, "memory": 6144}, "analyzer": {"cpu": 512, "memory": 4096}})
        deploy.verify_worker_resources({"collector": {"cpu": 1024, "memory": 8192}, "analyzer": {"cpu": 1024, "memory": 8192}})
        for collector, analyzer in [(4096, 4096), (6144, 2048), (6145, 4096)]:
            with self.subTest(collector=collector, analyzer=analyzer), self.assertRaisesRegex(RuntimeError, "sizing"):
                deploy.verify_worker_resources({"collector": {"cpu": 1024, "memory": collector}, "analyzer": {"cpu": 512, "memory": analyzer}})
        with self.assertRaisesRegex(RuntimeError, "sizing"):
            deploy.verify_worker_resources({"collector": {"cpu": 512, "memory": 6144}, "analyzer": {"cpu": 512, "memory": 4096}})

    def test_large_inventory_supported_sizes(self):
        for memory in (6144, 8192, 12288, 16384):
            deploy.verify_worker_resources({"collector": {"cpu": 2048, "memory": memory},
                                            "analyzer": {"cpu": 1024, "memory": 8192}})
        for memory in (8192, 16384, 30720):
            deploy.verify_worker_resources({"collector": {"cpu": 4096, "memory": memory},
                                            "analyzer": {"cpu": 1024, "memory": 8192}})
        for cpu, memory in ((2048, 4096), (2048, 6145), (2048, 17408), (4096, 6144), (4096, 31744), (4096, 16385), (8192, 16384)):
            with self.subTest(cpu=cpu, memory=memory), self.assertRaisesRegex(RuntimeError, "sizing"):
                deploy.verify_worker_resources({"collector": {"cpu": cpu, "memory": memory},
                                                "analyzer": {"cpu": 512, "memory": 4096}})

    def test_large_sizing_reconstructs_reviewed_source(self):
        import hashlib
        source = (deploy.INFRA / "variables.tf").read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), deploy.WORKER_SIZING_CURRENT_SHA256)
        for successor, predecessor in deploy.WORKER_SIZING_REVERSE:
            self.assertEqual(source.count(successor), 1)
            source = source.replace(successor, predecessor, 1)
        self.assertEqual(hashlib.sha256(source).hexdigest(), deploy.RUNTIME_LIMITS_CURRENT_SHA256)

    def test_stale_override_refused_before_variables_are_rewritten(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(deploy, "INFRA", Path(folder)):
            root = Path(folder)
            package = root / "api.zip"
            package.write_bytes(b"fixture")
            variables = root / "deployment.auto.tfvars.json"
            original = json.dumps({"worker_resources": {"collector": {"cpu": 512, "memory": 4096}, "analyzer": {"cpu": 512, "memory": 2048}}})
            variables.write_text(original)
            with self.assertRaisesRegex(RuntimeError, "sizing"):
                deploy.write_vars("fixture-image", package)
            self.assertEqual(variables.read_text(), original)

    def test_saved_task_sizes_and_telemetry_must_match(self):
        sizes = {"collector": {"cpu": 1024, "memory": 6144}, "analyzer": {"cpu": 512, "memory": 4096}}
        environment = {f"PEASO_{stage.upper()}_{suffix}": str(size[key] / 1024)
                       for stage, size in sizes.items() for suffix, key in [("VCPU", "cpu"), ("MEMORY_GIB", "memory")]}
        changes = []
        # This legacy unit isolates the sizing assertions; the full source,
        # image and embedded-configuration contract is exercised below.
        expected = {"worker_image": "fixture-image", "worker_resources": sizes,
                    "worker_environments": {}}
        for stage, size in sizes.items():
            env = dict(environment, PEASO_TASK_VCPU=str(size["cpu"] / 1024), PEASO_TASK_MEMORY_GIB=str(size["memory"] / 1024))
            expected["worker_environments"][stage] = env
            after = dict(size, family="hacktricks-cspm-" + stage,
                         container_definitions=json.dumps([{"image": "fixture-image", "environment": [{"name": key, "value": value} for key, value in env.items()]}]))
            changes.append({"address": 'aws_ecs_task_definition.tasks["' + stage + '"]', "index": stage,
                            "mode": "managed", "type": "aws_ecs_task_definition", "name": "tasks",
                            "change": {"actions": ["create"], "before": None, "after": after}})
        with tempfile.TemporaryDirectory() as folder:
            plan = Path(folder) / "review.tfplan"
            plan.write_bytes(b"fixture plan")
            response = SimpleNamespace(stdout=json.dumps({"resource_changes": changes}))
            with patch.object(deploy, "terraform", return_value=response), patch.object(deploy, "deployment_expectations", return_value=expected), contextlib.redirect_stdout(io.StringIO()):
                deploy.plan_summary(plan)
            container = json.loads(changes[0]["change"]["after"]["container_definitions"])
            next(item for item in container[0]["environment"] if item["name"] == "PEASO_ANALYZER_MEMORY_GIB")["value"] = "2"
            changes[0]["change"]["after"]["container_definitions"] = json.dumps(container)
            response.stdout = json.dumps({"resource_changes": changes})
            with patch.object(deploy, "terraform", return_value=response), patch.object(deploy, "deployment_expectations", return_value=expected), self.assertRaisesRegex(RuntimeError, "telemetry differs"):
                deploy.plan_summary(plan)


class ApplyTimeRuntimeGuards(unittest.TestCase):
    """Real Terraform 1.14 saved-plan shapes, isolated artifacts and SDK stubs."""
    @classmethod
    def setUpClass(cls):
        cls.account_patches = []
        if not re.fullmatch(r'[0-9]{12}', deploy.ACCOUNT):
            cls.account_patches = [patch.object(deploy, 'ACCOUNT', '111122223333'),
                patch.object(deploy, 'REPOSITORY',
                    '111122223333.dkr.ecr.us-east-1.amazonaws.com/hacktricks-cspm-worker')]
            for account_patch in cls.account_patches:
                account_patch.start()
        cls.folder = tempfile.TemporaryDirectory()
        cls.root = (Path(cls.folder.name) / "authored").resolve()
        cls.root.mkdir()
        cls.infra = cls.root / "infra/aws"
        cls.infra.mkdir(parents=True)
        cls.build = cls.infra / "build"
        GeneratedPackagePermissions().fixture_source(cls.root)
        for path in deploy.INFRA.glob("*.tf"):
            (cls.infra / path.name).write_bytes(path.read_bytes())
        (cls.infra / "customer-role.json").write_bytes((deploy.INFRA / "customer-role.json").read_bytes())
        cls.release = GeneratedPackagePermissions().build_under_umask(cls.root, cls.build, 0o077)
        cls.image = deploy.REPOSITORY + "@sha256:" + "a" * 64
        cls.variables = {"worker_image": cls.image, "source_version": cls.release["source_version"],
                         "api_zip": str((cls.build / "api.zip").resolve()), "region": "us-east-1",
                         "worker_resources": {"collector": {"cpu": 1024, "memory": 6144}, "analyzer": {"cpu": 512, "memory": 4096}},
                         "scan_runtime_limits": {"workflow_seconds": 3600, "stage_seconds": 1800, "lease_seconds": 3900},
                         "account_id": deploy.ACCOUNT,
                         "cognito_pool_id": "us-east-1_example", "cognito_client_id": "example-client",
                         "stripe_secret_arn": "", "stripe_price_id": "", "codex_token_secret_arn": ""}
        cls.fixture_deployment_values = {key: cls.variables[key] for key in (
            "account_id", "cognito_pool_id", "cognito_client_id", "stripe_secret_arn",
            "stripe_price_id", "codex_token_secret_arn")}
        cls.backend = cls.infra / ".terraform/terraform.tfstate"
        cls.backend.parent.mkdir()
        cls.backend.write_text(json.dumps({"backend": {"type": "s3", "config": {
            "bucket": "example-deployment-state", "key": "cspm/terraform.tfstate", "region": "us-east-1",
            "encrypt": True, "use_lockfile": True}}}))

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()
        for account_patch in reversed(cls.account_patches):
            account_patch.stop()

    def setUp(self):
        self.patches = [patch.object(deploy, key, value) for key, value in
                        (("ROOT", self.root), ("INFRA", self.infra), ("BUILD", self.build))]
        original_value = deploy.deployment.value
        self.patches.append(patch.object(deploy.deployment, "value",
            side_effect=lambda key: self.fixture_deployment_values[key]
                if key in self.fixture_deployment_values else original_value(key)))
        expected_backend = json.loads(self.backend.read_text())["backend"]["config"]
        self.patches.append(patch.object(deploy.deployment, "backend", return_value=expected_backend))
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        (self.infra / "deployment.auto.tfvars.json").write_text(json.dumps(self.variables))
        self.plan = self.build / "offline.tfplan"
        self.write_plan()
        self.data = {"variables": {k: {"value": v} for k, v in self.variables.items()}, "resource_changes": []}
        for stage, size in self.variables["worker_resources"].items():
            self.data["resource_changes"].append({"address": f'aws_ecs_task_definition.tasks["{stage}"]',
                "type": "aws_ecs_task_definition", "name": "tasks", "mode": "managed", "index": stage,
                "change": {"actions": ["create"], "before": None,
                           "after": dict(size, family="hacktricks-cspm-" + stage),
                           "after_unknown": {"container_definitions": True}}})
        code_hash = base64.b64encode(hashlib.sha256((self.build / "api.zip").read_bytes()).digest()).decode()
        package_key = deploy.api_package_key(code_hash)
        package_bucket = f"hacktricks-cspm-artifacts-{deploy.ACCOUNT}"
        package_kms_key = f"arn:aws:kms:us-east-1:{deploy.ACCOUNT}:key/00000000-0000-0000-0000-000000000000"
        for name, memory, timeout in (("api", 512, 28), ("scheduler", 256, 60)):
            self.data["resource_changes"].append({"address": "aws_lambda_function." + name,
                "type": "aws_lambda_function", "name": name, "mode": "managed",
                "change": {"actions": ["create"], "before": None, "after_unknown": {"environment": [{"variables": True}]},
                           "after": {"environment": [{}], "function_name": "hacktricks-cspm-" + name,
                                     "filename": None, "s3_bucket": package_bucket, "s3_key": package_key,
                                     "source_code_hash": code_hash,
                                     "memory_size": memory, "timeout": timeout, "runtime": "python3.12",
                                     "handler": "peaso.server." + ("lambda_handler" if name == "api" else "scheduler_handler") + ".handler",
                                     "architectures": ["x86_64"]}}})
        self.data["resource_changes"].append({"address": "aws_s3_object.api_zip",
            "type": "aws_s3_object", "name": "api_zip", "mode": "managed",
            "change": {"actions": ["no-op"], "before": None,
                       "after": {"id": package_bucket + "/" + package_key,
                                 "bucket": package_bucket, "key": package_key,
                                 "source": self.variables["api_zip"], "source_hash": code_hash,
                                 "metadata": {"sha256": hashlib.sha256((self.build / "api.zip").read_bytes()).hexdigest()},
                                 "server_side_encryption": "aws:kms", "kms_key_id": package_kms_key}}})

    def write_plan(self, corruption=None):
        with zipfile.ZipFile(self.plan, "w") as archive:
            for path in self.infra.glob("*.tf"):
                archive.writestr("tfconfig/m-/" + path.name, path.read_bytes() + (b"\n# tamper" if path.name == corruption else b""))
        self.digest = hashlib.sha256(self.plan.read_bytes()).hexdigest()

    def review(self):
        with patch.object(deploy, "terraform", return_value=SimpleNamespace(stdout=json.dumps(self.data))), contextlib.redirect_stdout(io.StringIO()):
            deploy.plan_summary(self.plan)
        return json.loads(self.plan.with_suffix(".review.json").read_text())

    def test_exact_savedplan_unknown_shapes_record_four_required_checks(self):
        review = self.review()
        self.assertEqual(review["counts"], {"create": 4, "update": 0, "delete": 0})
        self.assertEqual(len(review["required_resolved_checks"]), 4)
        self.assertTrue(review["resolved_validation_required"])
        self.assertEqual(review["sha256"], self.digest)
        self.assertEqual(stat.S_IMODE(self.plan.with_suffix(".review.json").stat().st_mode), 0o600)

    def test_missing_or_false_markers_refused(self):
        for index, markers in ((0, {}), (0, {"container_definitions": False}), (0, {"container_definitions": "true"}),
                               (2, {}), (2, {"environment": [{"variables": False}]}), (2, {"environment": True})):
            data = copy.deepcopy(self.data)
            self.data["resource_changes"][index]["change"]["after_unknown"] = markers
            with self.subTest(index=index, markers=markers), self.assertRaises(RuntimeError):
                self.review()
            self.data = data

    def test_mixed_known_unknown_and_known_tamper(self):
        contract = self.review()["resolved_contract"]
        lambda_change = self.data["resource_changes"][2]["change"]
        lambda_change["after"]["environment"] = [{"variables": {"PEASO_COLLECTOR_MEMORY_GIB": "6"}}]
        self.review()
        lambda_change["after"]["environment"][0]["variables"]["PEASO_COLLECTOR_MEMORY_GIB"] = "2"
        with self.assertRaisesRegex(RuntimeError, "telemetry differs"):
            self.review()
        lambda_change["after"]["environment"][0]["variables"] = {"PEASO_SOURCE_VERSION": "tampered"}
        with self.assertRaisesRegex(RuntimeError, "PEASO_SOURCE_VERSION"):
            self.review()
        lambda_change["after"]["environment"] = [{"variables": dict(contract["api_environment"])}]
        lambda_change["after"]["environment"][0]["variables"]["PEASO_AI_CREDENTIAL_SECRET_ARN"] = f"arn:aws:secretsmanager:us-east-1:{deploy.ACCOUNT}:secret:hacktricks-cspm-ai-key-Ab1234"
        # A per-key marker may defer just the credential ARN; every known key is checked.
        del lambda_change["after"]["environment"][0]["variables"]["PEASO_CREDENTIAL_SECRET_ARN"]
        lambda_change["after_unknown"] = {"environment": [{"variables": {"PEASO_CREDENTIAL_SECRET_ARN": True}}]}
        self.review()
        del lambda_change["after"]["environment"][0]["variables"]["PEASO_ANALYZER_MEMORY_GIB"]
        with self.assertRaisesRegex(RuntimeError, "PEASO_ANALYZER_MEMORY_GIB"):
            self.review()

    def test_known_container_image_environment_and_empty_definitions_refused(self):
        contract = self.review()["resolved_contract"]
        change = self.data["resource_changes"][1]["change"]
        environment = dict(contract["worker_environments"]["analyzer"])
        environment["PEASO_AI_CREDENTIAL_SECRET_ARN"] = f"arn:aws:secretsmanager:us-east-1:{deploy.ACCOUNT}:secret:hacktricks-cspm-ai-key-Ab1234"
        container = {"image": self.image, "environment": [{"name": k, "value": v} for k, v in environment.items()]}
        change["after"]["container_definitions"] = json.dumps([container])
        self.review()
        for image in (None, deploy.ZERO_IMAGE, deploy.REPOSITORY + "@sha256:" + "b" * 64):
            container["image"] = image
            change["after"]["container_definitions"] = json.dumps([container])
            with self.subTest(image=image), self.assertRaisesRegex(RuntimeError, "image differs"):
                self.review()
        change["after"]["container_definitions"] = "[]"
        with self.assertRaisesRegex(RuntimeError, "definitions missing"):
            self.review()

    def test_noncreate_unknown_refused(self):
        for actions in (["no-op"], ["update"], ["delete"], ["delete", "create"]):
            self.data["resource_changes"][0]["change"]["actions"] = actions
            with self.subTest(actions=actions), self.assertRaises(RuntimeError):
                self.review()

    def test_variables_source_sizing_and_embedded_config_tamper_refused(self):
        for key, value in (("worker_image", deploy.ZERO_IMAGE), ("worker_image", "mutable:latest"),
                           ("worker_image", deploy.REPOSITORY + "@sha256:" + "b" * 64),
                           ("source_version", "b" * 64), ("api_zip", "/unverified/package.zip"),
                           ("worker_resources", {"collector": {"cpu": 1024, "memory": 8192}, "analyzer": {"cpu": 512, "memory": 4096}})):
            original = copy.deepcopy(self.data)
            self.data["variables"][key]["value"] = value
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                self.review()
            self.data = original
        self.data["resource_changes"][0]["change"]["after"]["memory"] = 8192
        with self.assertRaisesRegex(RuntimeError, "task sizing differs"):
            self.review()
        self.data["resource_changes"][0]["change"]["after"]["memory"] = 6144
        self.write_plan("api.tf")
        with self.assertRaisesRegex(RuntimeError, "configuration differs"):
            self.review()

    def resolved_fixture(self):
        from unittest.mock import Mock
        review = self.review()
        contract = review["resolved_contract"]
        workflow = f"arn:aws:states:us-east-1:{deploy.ACCOUNT}:stateMachine:hacktricks-cspm"
        secret = f"arn:aws:secretsmanager:us-east-1:{deploy.ACCOUNT}:secret:hacktricks-cspm-credential-key-Ab1234"
        bucket = f"hacktricks-cspm-artifacts-{deploy.ACCOUNT}"
        outputs = {k: {"value": v} for k, v in {"workflow_arn": workflow, "credential_secret_arn": secret,
                   "artifact_bucket": bucket, "metadata_table": "hacktricks-cspm", "api_function": "hacktricks-cspm-api"}.items()}
        self.tasks, self.functions, states = {}, {}, {}
        for stage, state in (("collector", "Collect"), ("analyzer", "Analyze")):
            arn = f"arn:aws:ecs:us-east-1:{deploy.ACCOUNT}:task-definition/hacktricks-cspm-{stage}:1"
            env = dict(contract["worker_environments"][stage], PEASO_ARTIFACT_BUCKET=bucket)
            env["PEASO_AI_CREDENTIAL_SECRET_ARN"] = f"arn:aws:secretsmanager:us-east-1:{deploy.ACCOUNT}:secret:hacktricks-cspm-ai-key-Ab1234"
            if stage == "collector":
                env["PEASO_CREDENTIAL_SECRET_ARN"] = secret
            self.tasks[arn] = dict(contract["worker_resources"][stage], family="hacktricks-cspm-" + stage,
                status="ACTIVE", taskDefinitionArn=arn, containerDefinitions=[{"name": stage, "image": self.image,
                    "environment": [{"name": k, "value": v} for k, v in env.items()]}])
            states[state] = {"Parameters": {"TaskDefinition": arn, "Overrides": {"ContainerOverrides": [{"Name": stage,
                "Command.$": f"States.Array('{stage}', '--once', '--tenant-id', $.tenant_id, '--scan-id', $.scan_id)"}]}}}
        for name, config in review["lambda_configuration"].items():
            self.functions["hacktricks-cspm-" + name] = {
                "FunctionName": config["function_name"], "CodeSha256": config["source_code_hash"], "MemorySize": config["memory_size"],
                "Timeout": config["timeout"], "Runtime": config["runtime"], "Handler": config["handler"], "Architectures": config["architectures"],
                "State": "Active", "LastUpdateStatus": "Successful", "Environment": {"Variables": dict(contract["api_environment"],
                    PEASO_ARTIFACT_BUCKET=bucket, PEASO_CREDENTIAL_SECRET_ARN=secret, PEASO_WORKFLOW_ARN=workflow,
                    PEASO_AI_CREDENTIAL_SECRET_ARN=f"arn:aws:secretsmanager:us-east-1:{deploy.ACCOUNT}:secret:hacktricks-cspm-ai-key-Ab1234")}}
        session = Mock()
        clients = {name: Mock() for name in ("sts", "stepfunctions", "ecs", "lambda", "s3")}
        session.client.side_effect = clients.__getitem__
        clients["sts"].get_caller_identity.return_value = {"Account": deploy.ACCOUNT}
        clients["stepfunctions"].describe_state_machine.return_value = {"definition": json.dumps({"States": states})}
        clients["ecs"].describe_task_definition.side_effect = lambda taskDefinition: {"taskDefinition": self.tasks[taskDefinition]}
        clients["lambda"].get_function_configuration.side_effect = lambda FunctionName: self.functions[FunctionName]
        package = next(row["change"]["after"] for row in self.data["resource_changes"]
                       if row["address"] == "aws_s3_object.api_zip")
        clients["s3"].head_object.return_value = {"Metadata": package["metadata"],
            "ServerSideEncryption": "aws:kms", "SSEKMSKeyId": package["kms_key_id"],
            "ContentLength": (self.build / "api.zip").stat().st_size}
        self.states_client = clients["stepfunctions"]
        def terraform(*args, **kwargs):
            if args == ("show", "-json"):
                resources = [{"address": row["address"], "values": row["change"]["after"]}
                             for row in self.data["resource_changes"] if row["address"] in {
                                 "aws_s3_object.api_zip", "aws_lambda_function.api", "aws_lambda_function.scheduler"}]
                return SimpleNamespace(stdout=json.dumps({"values": {"root_module": {"resources": resources}}}))
            return SimpleNamespace(stdout=json.dumps(outputs if args[0] == "output" else self.data))
        return session, terraform

    def test_resolved_actual_values_using_sdk_stubs(self):
        session, terraform = self.resolved_fixture()
        with patch.object(deploy, "terraform", side_effect=terraform), contextlib.redirect_stdout(io.StringIO()):
            receipt = deploy.verify_resolved_deployment(session, self.plan, self.digest)
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(stat.S_IMODE(self.plan.with_suffix(".resolved.json").stat().st_mode), 0o600)
        self.assertNotIn("Environment", json.dumps(receipt))

    def test_resolved_missing_unknown_mismatch_and_wrong_revision_fail_closed(self):
        for mutation in ("cpu", "image", "missing-env", "unknown-env", "worker-source", "lambda-cost", "lambda-source-url",
                         "lambda-code", "lambda-env-missing", "wrong-revision", "workflow-override"):
            session, terraform = self.resolved_fixture()
            task = next(iter(self.tasks.values()))
            container = task["containerDefinitions"][0]
            function = self.functions["hacktricks-cspm-api"]
            if mutation == "cpu": task["cpu"] = 512
            elif mutation == "image": container["image"] = deploy.ZERO_IMAGE
            elif mutation == "missing-env": container["environment"].pop()
            elif mutation == "unknown-env": container["environment"][0]["value"] = None
            elif mutation == "worker-source": next(i for i in container["environment"] if i["name"] == "PEASO_SOURCE_VERSION")["value"] = "unknown"
            elif mutation == "lambda-cost": function["Environment"]["Variables"]["PEASO_COLLECTOR_MEMORY_GIB"] = "2"
            elif mutation == "lambda-source-url": function["Environment"]["Variables"]["PEASO_SOURCE_URL"] = "unknown"
            elif mutation == "lambda-code": function["CodeSha256"] = "tampered"
            elif mutation == "lambda-env-missing": function["Environment"] = {}
            elif mutation == "wrong-revision": task["taskDefinitionArn"] = task["taskDefinitionArn"].replace(":1", ":2")
            elif mutation == "workflow-override":
                definition = json.loads(self.states_client.describe_state_machine.return_value["definition"])
                definition["States"]["Collect"]["Parameters"]["Overrides"]["Cpu"] = "256"
                self.states_client.describe_state_machine.return_value = {"definition": json.dumps(definition)}
            with self.subTest(mutation=mutation), patch.object(deploy, "terraform", side_effect=terraform), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError):
                deploy.verify_resolved_deployment(session, self.plan, self.digest)

    def test_publication_stops_before_mutation_on_failed_resolution(self):
        for command in ("publish-frontend",):
            with self.subTest(command=command), patch.object(sys, "argv", ["peaso_deploy.py", command,
                    "--plan", str(self.plan), "--reviewed-sha256", self.digest]), \
                    patch.object(deploy, "aws_identity"), \
                    patch.object(deploy, "verify_resolved_deployment", side_effect=RuntimeError("Unresolved runtime")) as verify, \
                    patch.object(deploy, "run") as run, self.assertRaisesRegex(RuntimeError, "Unresolved runtime"):
                deploy.main()
            verify.assert_called_once()
            run.assert_not_called()


class CloudFrontRecoveryGuards(unittest.TestCase):
    """Offline, exact-baseline fixtures; no AWS/provider/network calls."""
    setUpClass = classmethod(ApplyTimeRuntimeGuards.setUpClass.__func__)
    tearDownClass = classmethod(ApplyTimeRuntimeGuards.tearDownClass.__func__)
    write_plan = ApplyTimeRuntimeGuards.write_plan

    def test_live_state_native_variable_check_row_reordering_only(self):
        addresses = ["var.source_version", "var.worker_image", "var.worker_resources",
                     "var.scan_runtime_limits", "var.monthly_budget_usd", "var.region"]
        state = {"version": 4, "terraform_version": "1.14.3", "serial": 5, "lineage": "owned-lineage",
                 "outputs": {"api": {"value": "owned"}},
                 "resources": [{"instances": [{"attributes": {"id": "owned", "enabled": False}}]}],
                 "check_results": [{"object_kind": "var", "config_addr": address, "status": "pass",
                                    "objects": [{"object_addr": address, "status": "pass"}]} for address in addresses]}
        pulled = copy.deepcopy(state)
        pulled["check_results"] = [pulled["check_results"][i] for i in (2, 3, 4, 5, 0, 1)]
        self.assertTrue(deploy.recovery_live_state_matches(pulled, state))
        self.assertTrue(deploy.recovery_live_state_matches(state, state))
        original = copy.deepcopy(pulled)
        for mutation in ("row", "status", "object", "duplicate", "attribute", "serial", "lineage", "output",
                         "terraform-version", "version", "missing-checks", "null-checks", "bool-attribute"):
            pulled = copy.deepcopy(original)
            if mutation == "row": pulled["check_results"][0]["config_addr"] = "var.other"
            elif mutation == "status": pulled["check_results"][0]["status"] = "fail"
            elif mutation == "object": pulled["check_results"][0]["objects"][0]["object_addr"] = "var.other"
            elif mutation == "duplicate": pulled["check_results"][0] = copy.deepcopy(pulled["check_results"][1])
            elif mutation == "attribute": pulled["resources"][0]["instances"][0]["attributes"]["id"] = "other"
            elif mutation == "serial": pulled["serial"] += 1
            elif mutation == "lineage": pulled["lineage"] = "other"
            elif mutation == "output": pulled["outputs"]["api"]["value"] = "other"
            elif mutation == "terraform-version": pulled["terraform_version"] = "1.15.0"
            elif mutation == "version": pulled["version"] += 1
            elif mutation == "missing-checks": pulled.pop("check_results")
            elif mutation == "null-checks": pulled["check_results"] = None
            else: pulled["resources"][0]["instances"][0]["attributes"]["enabled"] = 0
            with self.subTest(mutation=mutation):
                self.assertFalse(deploy.recovery_live_state_matches(pulled, state))
        duplicate = copy.deepcopy(state)
        duplicate["check_results"].append(copy.deepcopy(duplicate["check_results"][0]))
        reordered = copy.deepcopy(duplicate)
        reordered["check_results"].reverse()
        self.assertTrue(deploy.recovery_live_state_matches(reordered, duplicate))
        self.assertFalse(deploy.recovery_live_state_matches(duplicate, state))
        nested = copy.deepcopy(state)
        nested["check_results"][0]["objects"].append({"object_addr": "second", "status": "pass"})
        changed_nested = copy.deepcopy(nested)
        changed_nested["check_results"][0]["objects"].reverse()
        self.assertFalse(deploy.recovery_live_state_matches(changed_nested, nested))

    def setUp(self):
        ApplyTimeRuntimeGuards.setUp(self)
        contract = deploy.deployment_expectations(self.data, self.plan)
        self.state = {"version": 4, "lineage": "offline-cspm-lineage", "serial": 5, "resources": []}
        for r in self.data["resource_changes"]:
            if r["address"] == "aws_s3_object.api_zip":
                r["change"]["before"] = copy.deepcopy(r["change"]["after"])
                continue
            after = r["change"]["after"]
            if r["type"] == "aws_ecs_task_definition":
                env = dict(contract["worker_environments"][r["index"]])
                env["PEASO_AI_CREDENTIAL_SECRET_ARN"] = f"arn:aws:secretsmanager:us-east-1:{deploy.ACCOUNT}:secret:hacktricks-cspm-ai-key-Ab1234"
                if r["index"] == "collector":
                    env["PEASO_CREDENTIAL_SECRET_ARN"] = f"arn:aws:secretsmanager:us-east-1:{deploy.ACCOUNT}:secret:hacktricks-cspm-credential-key-Ab1234"
                after["container_definitions"] = json.dumps([{"name": r["index"], "image": self.image,
                    "environment": [{"name": k, "value": v} for k, v in env.items()], "user": "10001:10001"}])
                r["change"]["actions"] = ["delete", "create"]
            else:
                env = dict(contract["api_environment"])
                env["PEASO_AI_CREDENTIAL_SECRET_ARN"] = f"arn:aws:secretsmanager:us-east-1:{deploy.ACCOUNT}:secret:hacktricks-cspm-ai-key-Ab1234"
                env["PEASO_CREDENTIAL_SECRET_ARN"] = f"arn:aws:secretsmanager:us-east-1:{deploy.ACCOUNT}:secret:hacktricks-cspm-credential-key-Ab1234"
                after["environment"] = [{"variables": env}]
                r["change"]["actions"] = ["update"]
            before = copy.deepcopy(after)
            before["id"] = "owned-" + r["address"]
            if r["type"] == "aws_ecs_task_definition":
                containers = json.loads(before["container_definitions"])
                containers[0]["image"] = deploy.REPOSITORY + "@sha256:" + "b" * 64
                next(e for e in containers[0]["environment"] if e["name"] == "PEASO_SOURCE_VERSION")["value"] = "0" * 64
                before["container_definitions"] = json.dumps(containers)
                r["change"]["after_unknown"] = {"id": True}
            else:
                before["environment"][0]["variables"]["PEASO_SOURCE_VERSION"] = "0" * 64
                before["environment"][0]["variables"]["PEASO_SOURCE_URL"] = "https://cspm.hacktricks.wiki/source/old.zip"
                after["id"] = before["id"]
                r["change"]["after_unknown"] = {}
            r["change"]["before"] = before
        for address, field in (("aws_sfn_state_machine.scan", "definition"), ("aws_iam_role_policy.workflow", "policy")):
            resource_type, name = address.split(".")
            before = {"id": "owned-" + address, "name": "hacktricks-cspm", field: '{"owned": "reference"}'}
            if address == "aws_iam_role_policy.workflow":
                before.update(name="terraform-20260101000000000000000001", name_prefix="terraform-",
                              role="hacktricks-cspm-workflow")
                before["id"] = before["role"] + ":" + before["name"]
            self.data["resource_changes"].append({"address": address, "mode": "managed", "type": resource_type, "name": name,
                "change": {"actions": ["update"], "before": before,
                           "after": {k: v for k, v in before.items() if k != field},
                           "after_unknown": {field: True}}})
        for r in self.data["resource_changes"]:
            instance = {"attributes": copy.deepcopy(r["change"]["before"])}
            if "index" in r:
                instance["index_key"] = r["index"]
            self.state["resources"].append({"mode": "managed", "type": r["type"], "name": r["name"], "instances": [instance]})
        for address in sorted(deploy.RECOVERY_MISSING):
            resource_type, tail = address.split(".")
            name = tail.split("[")[0]
            values = {"name": "cspm.hacktricks.wiki"} if resource_type == "aws_route53_record" else {}
            self.data["resource_changes"].append({"address": address, "mode": "managed", "type": resource_type, "name": name,
                "change": {"actions": ["create"], "before": None, "after": values, "after_unknown": {}}})
        for resource_type in ("aws_ecr_repository", "aws_ecr_lifecycle_policy"):
            values = {"id": "owned-bootstrap-" + resource_type, "repository": "hacktricks-cspm-worker"}
            self.data["resource_changes"].append({"address": resource_type + ".worker", "mode": "managed", "type": resource_type, "name": "worker",
                "change": {"actions": ["no-op"], "before": values, "after": copy.deepcopy(values), "after_unknown": {}}})
            self.state["resources"].append({"mode": "managed", "type": resource_type, "name": "worker",
                                            "instances": [{"attributes": copy.deepcopy(values)}]})
        self.data["prior_state"] = {"values": {"root_module": {"resources": [
            {"address": r["address"], "mode": "managed", "values": copy.deepcopy(r["change"]["before"])}
            for r in self.data["resource_changes"] if r["change"]["before"] is not None]}}}
        initial = copy.deepcopy(self.data)
        for r in initial["resource_changes"]:
            if r["change"]["actions"] != ["no-op"] or r["address"] == "aws_s3_object.api_zip":
                r["change"]["actions"], r["change"]["before"] = ["create"], None
        prior = self.build / "failed.tfplan"
        prior.write_bytes(self.plan.read_bytes())
        self.baseline = {"schema": "peaso-cloudfront-recovery-v1", "account": deploy.ACCOUNT,
                         "backend": deploy.RECOVERY_BACKEND, "approved_actions": {
                             k: {"actions": v[0], "reason": v[1]} for k, v in deploy.RECOVERY_ACTIONS.items()}}
        self.baseline["failed_plan"] = {"path": str(prior), "sha256": hashlib.sha256(prior.read_bytes()).hexdigest()}
        self.artifact("failed_plan_json", initial)
        self.artifact("state", self.state)
        self.artifact("drift", {"resource_drift": [], "prior_state": self.data["prior_state"], "resource_changes": []})
        self.artifact("orphans_and_jobs", {"account": deploy.ACCOUNT, "backend": deploy.RECOVERY_BACKEND,
                                         "orphan_resources": [], "active_hosted_jobs": []})
        for key, value in (("RECOVERY_FAILED_PLAN_SHA256", self.baseline["failed_plan"]["sha256"]),
                           ("RECOVERY_FAILED_JSON_SHA256", self.baseline["failed_plan_json"]["sha256"])):
            p = patch.object(deploy, key, value)
            p.start()
            self.addCleanup(p.stop)
        self.baseline_path = self.build / "baseline.json"
        self.save_baseline()

    def artifact(self, key, value):
        path = self.build / ("fixture-" + key + ".json")
        path.write_text(json.dumps(value))
        self.baseline[key] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def save_baseline(self):
        self.baseline_path.write_text(json.dumps(self.baseline))
        self.baseline_digest = hashlib.sha256(self.baseline_path.read_bytes()).hexdigest()

    def review(self):
        with patch.object(deploy, "terraform", return_value=SimpleNamespace(stdout=json.dumps(self.data))), contextlib.redirect_stdout(io.StringIO()):
            deploy.plan_summary(self.plan, recovery_baseline=self.baseline_path, recovery_sha256=self.baseline_digest)
        return json.loads(self.plan.with_suffix(".review.json").read_text())

    def test_exact_source_recovery_inventory_and_reasons(self):
        report = self.review()
        self.assertEqual(report["counts"], {"create": 6, "update": 4, "delete": 2})
        self.assertEqual(report["recovery"]["baseline_sha256"], self.baseline_digest)
        self.assertTrue(report["resolved_validation_required"])
        self.assertEqual(len(report["resources"]), 10)
        self.assertTrue(all(r.get("reason") for r in report["resources"]))

    def test_owned_generated_workflow_policy_name_passes_full_plan_review(self):
        policy = next(r for r in self.data["resource_changes"] if r["address"] == "aws_iam_role_policy.workflow")
        self.assertTrue(policy["change"]["after"]["name"].startswith("terraform-"))
        report = self.review()
        self.assertEqual(report["counts"], {"create": 6, "update": 4, "delete": 2})
        row = next(r for r in report["resources"] if r["address"] == policy["address"])
        self.assertEqual(row["reason"], "workflow-iam-task-references")

    def test_generated_workflow_name_renamed_rebound_or_unowned_refused(self):
        original = copy.deepcopy(self.data)
        for mutation in ("name", "role", "id", "unowned-before", "other-address"):
            self.data = copy.deepcopy(original)
            policy = next(r for r in self.data["resource_changes"] if r["address"] == "aws_iam_role_policy.workflow")
            if mutation == "name": policy["change"]["after"]["name"] = "terraform-renamed"
            elif mutation == "role": policy["change"]["after"]["role"] = "hacktricks-cspm-api"
            elif mutation == "id": policy["change"]["after"]["id"] = "hacktricks-cspm-workflow:other"
            elif mutation == "unowned-before": policy["change"]["before"]["id"] = "unowned:policy"
            else: policy["address"] = "aws_iam_role_policy.unowned"
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                self.review()

    def test_generated_workflow_name_requires_known_complete_baseline_binding(self):
        original_data, original_state = copy.deepcopy(self.data), copy.deepcopy(self.state)
        for mutation in ("empty-name", "missing-role", "wrong-role", "wrong-id-binding"):
            self.data, self.state = copy.deepcopy(original_data), copy.deepcopy(original_state)
            policy = next(r for r in self.data["resource_changes"] if r["address"] == "aws_iam_role_policy.workflow")
            before = policy["change"]["before"]
            if mutation == "empty-name": before["name"] = ""
            elif mutation == "missing-role": before.pop("role")
            elif mutation == "wrong-role": before["role"] = "hacktricks-cspm-api"
            else: before["id"] = "hacktricks-cspm-workflow:other-name"
            policy["change"]["after"] = {k: v for k, v in before.items() if k != "policy"}
            for r in self.state["resources"]:
                if r["type"] == policy["type"] and r["name"] == policy["name"]:
                    r["instances"][0]["attributes"] = copy.deepcopy(before)
            for r in self.data["prior_state"]["values"]["root_module"]["resources"]:
                if r["address"] == policy["address"]: r["values"] = copy.deepcopy(before)
            self.artifact("state", self.state)
            self.artifact("drift", {"resource_drift": [], "prior_state": self.data["prior_state"], "resource_changes": []})
            self.save_baseline()
            with self.subTest(mutation=mutation), self.assertRaisesRegex(RuntimeError, "name/role/id binding"):
                self.review()

    def provider_recovery_defaults(self):
        """Exact default settings and marker shapes from the rejected saved plan."""
        volume = [{"name": "scratch", "configure_at_launch": False, "host_path": "",
                   "docker_volume_configuration": [], "efs_volume_configuration": [],
                   "fsx_windows_file_server_volume_configuration": [], "s3files_volume_configuration": []}]
        for r in self.data["resource_changes"]:
            change = r["change"]
            if r["type"] == "aws_ecs_task_definition":
                old_container = json.loads(change["before"]["container_definitions"])[0]
                new_container = json.loads(change["after"]["container_definitions"])[0]
                old_container.update(portMappings=[], volumesFrom=[], systemControls=[],
                                     linuxParameters={"capabilities": {"add": [], "drop": ["ALL"]}})
                new_container["linuxParameters"] = {"capabilities": {"drop": ["ALL"]}}
                change["before"]["container_definitions"] = json.dumps([old_container])
                change["after"]["container_definitions"] = json.dumps([new_container])
                change["before"].update(enable_fault_injection=False, volume=copy.deepcopy(volume),
                                        ipc_mode="", pid_mode="", tags={}, requires_compatibilities=["FARGATE"],
                                        runtime_platform=[{"cpu_architecture": "X86_64"}])
                change["after"].update(volume=[{k: v for k, v in volume[0].items() if k != "configure_at_launch"}],
                                       ipc_mode=None, pid_mode=None, tags=None, requires_compatibilities=["FARGATE"],
                                       runtime_platform=[{"cpu_architecture": "X86_64"}])
                change["after_unknown"].update(enable_fault_injection=True,
                    volume=[{"configure_at_launch": True, "docker_volume_configuration": [],
                             "efs_volume_configuration": [], "fsx_windows_file_server_volume_configuration": [],
                             "s3files_volume_configuration": []}],
                    requires_compatibilities=[False], runtime_platform=[{}])
            elif r["type"] == "aws_lambda_function":
                change["before"]["tags"] = {}
                change["after"]["tags"] = {}
                change["after_unknown"].update(architectures=[False], ephemeral_storage=[{}],
                    logging_config=[{}], tracing_config=[{}], environment=[{"variables": {}}])
            elif r["type"] == "aws_sfn_state_machine":
                change["after_unknown"].update(logging_configuration=[{}], tracing_configuration=[{}],
                                              encryption_configuration=[{}])
            if change["before"] is not None:
                for state in self.state["resources"]:
                    address = state["type"] + "." + state["name"]
                    instance = state["instances"][0]
                    if "index_key" in instance:
                        address += '[' + json.dumps(instance["index_key"]) + ']'
                    if address == r["address"]:
                        instance["attributes"] = copy.deepcopy(change["before"])
                for prior in self.data["prior_state"]["values"]["root_module"]["resources"]:
                    if prior["address"] == r["address"]:
                        prior["values"] = copy.deepcopy(change["before"])
        self.artifact("state", self.state)
        self.artifact("drift", {"resource_drift": [], "prior_state": self.data["prior_state"], "resource_changes": []})
        self.save_baseline()

    def test_recursive_literal_boolean_markers_and_malformed_leaves(self):
        for marker in (False, {}, [], [False], [{}], {"nested": [False, {"leaf": False}]}):
            with self.subTest(marker=marker):
                self.assertFalse(deploy.recovery_unknown(marker))
        self.assertTrue(deploy.recovery_unknown({"nested": [False, {"leaf": True}]}))
        for marker in (None, 0, 1, "false", [True, 1], {"nested": [None]}, {1: False}):
            with self.subTest(marker=marker), self.assertRaisesRegex(RuntimeError, "Malformed"):
                deploy.recovery_unknown(marker)

    def test_provider_false_markers_and_exact_computed_defaults_accept(self):
        self.provider_recovery_defaults()
        report = self.review()
        self.assertEqual(report["counts"], {"create": 6, "update": 4, "delete": 2})
        self.assertEqual(set(report["resolved_contract"]["recovery_ecs_defaults"]), {"collector", "analyzer"})
        self.assertEqual(sum(c["field"] == "ecs_recovery_defaults" for c in report["required_resolved_checks"]), 2)
        resource = self.data["resource_changes"][-1]
        resource["change"]["after_unknown"] = {"nested": [False, {}]}
        self.review()  # A no-op with false-only markers is still completely known.
        resource["change"]["after_unknown"] = {"nested": [{"leaf": True}]}
        with self.assertRaisesRegex(RuntimeError, "completely known"):
            self.review()

    def test_provider_defaults_known_tamper_true_unknowns_and_malformed_refused(self):
        self.provider_recovery_defaults()
        original = copy.deepcopy(self.data)
        mutations = ("fault-true", "fault-integer", "fault-no-marker", "volume-launch-true", "volume-host",
                     "volume-name", "volume-extra", "volume-no-marker", "volume-unknown-host", "ipc", "pid", "tags",
                     "runtime-true", "architecture-true", "logging-known", "lambda-env-true", "role", "container-env",
                     "unrelated-empty", "sfn-logging-true", "sfn-tracing-true", "sfn-encryption-true", "malformed", "malformed-root")
        for mutation in mutations:
            self.data = copy.deepcopy(original)
            task, function = self.data["resource_changes"][0]["change"], self.data["resource_changes"][2]["change"]
            after, unknown = task["after"], task["after_unknown"]
            if mutation == "fault-true": after["enable_fault_injection"] = True
            elif mutation == "fault-integer": after["enable_fault_injection"] = 0
            elif mutation == "fault-no-marker": unknown.pop("enable_fault_injection")
            elif mutation == "volume-launch-true": after["volume"][0]["configure_at_launch"] = True
            elif mutation == "volume-host": after["volume"][0]["host_path"] = "/host"
            elif mutation == "volume-name": after["volume"][0]["name"] = "other"
            elif mutation == "volume-extra": after["volume"].append({"name": "other"})
            elif mutation == "volume-no-marker": unknown["volume"][0].pop("configure_at_launch")
            elif mutation == "volume-unknown-host": unknown["volume"][0]["host_path"] = True
            elif mutation == "ipc": after["ipc_mode"] = "host"
            elif mutation == "pid": after["pid_mode"] = "host"
            elif mutation == "tags": after["tags"] = {"unreviewed": "yes"}
            elif mutation == "runtime-true": unknown["runtime_platform"] = [{"cpu_architecture": True}]
            elif mutation == "architecture-true": function["after_unknown"]["architectures"] = [True]
            elif mutation == "logging-known": function["after"]["logging_config"] = [{"log_format": "JSON"}]
            elif mutation == "lambda-env-true": function["after_unknown"]["environment"] = [{"variables": {"PEASO_SOURCE_VERSION": True}}]
            elif mutation == "role": after["execution_role_arn"] = "arn:aws:iam::999999999999:role/other"
            elif mutation == "container-env":
                containers = json.loads(after["container_definitions"])
                containers[0]["environment"].append({"name": "UNREVIEWED", "value": "yes"})
                after["container_definitions"] = json.dumps(containers)
            elif mutation == "unrelated-empty": function["after"]["tags"] = None
            elif mutation.startswith("sfn-"):
                sfn = next(r for r in self.data["resource_changes"] if r["type"] == "aws_sfn_state_machine")
                field = mutation.split("-")[1] + "_configuration"
                sfn["change"]["after_unknown"][field] = [{"nested": True}]
            elif mutation == "malformed": unknown["runtime_platform"] = [{"cpu_architecture": "false"}]
            elif mutation == "malformed-root": task["after_unknown"] = []
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                self.review()

    def test_actual_resolved_recovery_defaults_and_mismatches(self):
        self.provider_recovery_defaults()
        session, terraform = ApplyTimeRuntimeGuards.resolved_fixture(self)
        for task in self.tasks.values():
            task.update(enableFaultInjection=False, volumes=[{"name": "scratch", "host": {}, "configureAtLaunch": False}])
            stage = task["containerDefinitions"][0]["name"]
            planned = next(r for r in self.data["resource_changes"] if r.get("index") == stage)
            task["containerDefinitions"] = json.loads(planned["change"]["after"]["container_definitions"])
        original = copy.deepcopy(self.tasks)
        def verify():
            with patch.object(deploy, "terraform", side_effect=terraform), contextlib.redirect_stdout(io.StringIO()):
                return deploy.verify_resolved_deployment(session, self.plan, self.digest,
                    recovery_baseline=self.baseline_path, recovery_sha256=self.baseline_digest)
        self.assertEqual(verify()["status"], "passed")
        for mutation in ("fault-true", "fault-null", "fault-integer", "volume-launch-true", "volume-host", "volume-name",
                         "volume-extra", "volume-efs", "volume-missing", "ipc", "pid", "port", "mount", "sysctl",
                         "cap-add", "cap-drop", "user", "container-env", "image"):
            self.tasks = copy.deepcopy(original)
            task = next(iter(self.tasks.values()))
            if mutation == "fault-true": task["enableFaultInjection"] = True
            elif mutation == "fault-null": task["enableFaultInjection"] = None
            elif mutation == "fault-integer": task["enableFaultInjection"] = 0
            elif mutation == "volume-launch-true": task["volumes"][0]["configureAtLaunch"] = True
            elif mutation == "volume-host": task["volumes"][0]["host"] = {"sourcePath": "/host"}
            elif mutation == "volume-name": task["volumes"][0]["name"] = "other"
            elif mutation == "volume-extra": task["volumes"].append({"name": "other"})
            elif mutation == "volume-efs": task["volumes"][0]["efsVolumeConfiguration"] = {"fileSystemId": "fs-other"}
            elif mutation == "volume-missing": task.pop("volumes")
            elif mutation == "ipc": task["ipcMode"] = "host"
            elif mutation == "pid": task["pidMode"] = "host"
            elif mutation == "port": task["containerDefinitions"][0]["portMappings"] = [{"containerPort": 80}]
            elif mutation == "mount": task["containerDefinitions"][0]["volumesFrom"] = [{"sourceContainer": "other"}]
            elif mutation == "sysctl": task["containerDefinitions"][0]["systemControls"] = [{"namespace": "net.ipv4.ip_forward", "value": "1"}]
            elif mutation == "cap-add": task["containerDefinitions"][0]["linuxParameters"]["capabilities"]["add"] = ["SYS_ADMIN"]
            elif mutation == "cap-drop": task["containerDefinitions"][0]["linuxParameters"]["capabilities"]["drop"] = []
            elif mutation == "user": task["containerDefinitions"][0]["user"] = "0:0"
            elif mutation == "container-env": task["containerDefinitions"][0]["environment"].append({"name": "UNREVIEWED", "value": "yes"})
            elif mutation == "image": task["containerDefinitions"][0]["image"] = deploy.ZERO_IMAGE
            self.plan.with_suffix(".resolved.json").unlink(missing_ok=True)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(RuntimeError, "ECS default-false/scratch/IPC/PID|container security/settings|image differs"):
                verify()
            self.assertFalse(self.plan.with_suffix(".resolved.json").exists())

    def test_actual_sdk_omitted_fault_and_container_cpu_zero(self):
        """Both owned revision-1 SDK receipts omit fault and add container cpu=0."""
        self.provider_recovery_defaults()
        session, terraform = ApplyTimeRuntimeGuards.resolved_fixture(self)
        for task in self.tasks.values():
            self.assertNotIn("enableFaultInjection", task)
            self.assertTrue(task["taskDefinitionArn"].endswith(":1"))
            task["volumes"] = [{"name": "scratch", "host": {}}]
            stage = task["containerDefinitions"][0]["name"]
            planned = next(r for r in self.data["resource_changes"] if r.get("index") == stage)
            container = json.loads(planned["change"]["after"]["container_definitions"])[0]
            self.assertNotIn("cpu", json.loads(planned["change"]["before"]["container_definitions"])[0])
            container["cpu"] = 0
            task["containerDefinitions"] = [container]
        original, original_data = copy.deepcopy(self.tasks), copy.deepcopy(self.data)
        def verify():
            with patch.object(deploy, "terraform", side_effect=terraform), contextlib.redirect_stdout(io.StringIO()):
                return deploy.verify_resolved_deployment(session, self.plan, self.digest,
                    recovery_baseline=self.baseline_path, recovery_sha256=self.baseline_digest)
        self.assertEqual(verify()["status"], "passed")
        self.assertEqual(stat.S_IMODE(self.plan.with_suffix(".resolved.json").stat().st_mode), 0o600)
        for mutation in ("fault-true", "fault-null", "fault-zero", "fault-string", "cpu-bool", "cpu-float",
                         "cpu-nonzero", "cpu-null", "extra-setting", "role", "env", "source-env", "wrong-image"):
            self.tasks, self.data = copy.deepcopy(original), copy.deepcopy(original_data)
            task = next(iter(self.tasks.values()))
            container = task["containerDefinitions"][0]
            if mutation.startswith("fault-"):
                task["enableFaultInjection"] = {"true": True, "null": None, "zero": 0, "string": "false"}[mutation[6:]]
            elif mutation.startswith("cpu-"):
                container["cpu"] = {"bool": False, "float": 0.0, "nonzero": 1, "null": None}[mutation[4:]]
            elif mutation == "extra-setting": container["privileged"] = True
            elif mutation == "role":
                # Role immutability is checked while revalidating the saved plan.
                self.data["resource_changes"][0]["change"]["after"]["execution_role_arn"] = "arn:aws:iam::999999999999:role/other"
            elif mutation == "env": container["environment"].append({"name": "UNREVIEWED", "value": "yes"})
            elif mutation == "source-env":
                next(e for e in container["environment"] if e["name"] == "PEASO_SOURCE_VERSION")["value"] = "0" * 64
            elif mutation == "wrong-image": container["image"] = deploy.REPOSITORY + "@sha256:" + "b" * 64
            self.plan.with_suffix(".resolved.json").unlink(missing_ok=True)
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                verify()
            self.assertFalse(self.plan.with_suffix(".resolved.json").exists())

    def test_container_cpu_equivalence_is_only_absent_to_literal_integer_zero(self):
        for before, after in (({}, {"cpu": 0}), ({"cpu": 0}, {})):
            with self.subTest(before=before, after=after):
                self.assertTrue(deploy.recovery_container_settings_match(before, after))
        for invalid in (False, True, 0.0, 1, -1, None, "0"):
            for before, after in (({}, {"cpu": invalid}), ({"cpu": invalid}, {})):
                with self.subTest(before=before, after=after):
                    self.assertFalse(deploy.recovery_container_settings_match(before, after))
        for before, after in (({"cpu": 1}, {"cpu": 0}), ({"cpu": 0}, {"cpu": 1}),
                              ({"extra": {}}, {"extra": {"cpu": 0}}),
                              ({"linuxParameters": {}}, {"linuxParameters": {"cpu": 0}})):
            with self.subTest(before=before, after=after):
                self.assertFalse(deploy.recovery_container_settings_match(before, after))

    def test_only_four_prior_literal_empty_container_paths_normalize(self):
        self.provider_recovery_defaults()
        original = copy.deepcopy(self.data)
        for mutation in ("port", "mount", "sysctl", "cap-add", "cap-drop", "port-null"):
            self.data = copy.deepcopy(original)
            change = self.data["resource_changes"][0]["change"]
            container = json.loads(change["after"]["container_definitions"])[0]
            if mutation == "port": container["portMappings"] = [{"containerPort": 80}]
            elif mutation == "mount": container["volumesFrom"] = [{"sourceContainer": "other"}]
            elif mutation == "sysctl": container["systemControls"] = [{"namespace": "net.ipv4.ip_forward", "value": "1"}]
            elif mutation == "cap-add": container["linuxParameters"]["capabilities"]["add"] = ["SYS_ADMIN"]
            elif mutation == "cap-drop": container["linuxParameters"]["capabilities"]["drop"] = []
            elif mutation == "port-null": container["portMappings"] = None
            change["after"]["container_definitions"] = json.dumps([container])
            with self.subTest(mutation=mutation), self.assertRaisesRegex(RuntimeError, "unrelated container"):
                self.review()
        self.assertFalse(deploy.recovery_container_settings_match({"portMappings": None}, {}))
        self.assertFalse(deploy.recovery_container_settings_match({}, {"portMappings": []}))

    def test_default_stays_create_only_and_recovery_flags_are_paired(self):
        with patch.object(deploy, "terraform", return_value=SimpleNamespace(stdout=json.dumps(self.data))):
            with self.assertRaisesRegex(RuntimeError, "Destructive"):
                deploy.plan_summary(self.plan)
            for kwargs in ({"recovery_baseline": self.baseline_path}, {"recovery_sha256": self.baseline_digest},
                           {"bootstrap": True, "recovery_baseline": self.baseline_path, "recovery_sha256": self.baseline_digest}):
                # Flag names only: xdist cannot serialize the Path values in subtest reports.
                with self.subTest(flags=sorted(kwargs)), self.assertRaisesRegex(RuntimeError, "Recovery requires"):
                    deploy.plan_summary(self.plan, **kwargs)

    def test_unrelated_update_delete_replacement_create_identity_and_known_tamper_refused(self):
        original = copy.deepcopy(self.data)
        mutations = ("delete", "other-replacement", "wrong-id", "old-source", "wrong-image", "size", "container-user", "lambda-extra-env", "unrelated-update", "unknown-before")
        for mutation in mutations:
            self.data = copy.deepcopy(original)
            task, function = self.data["resource_changes"][0], self.data["resource_changes"][2]
            if mutation == "delete": task["change"]["actions"] = ["delete"]
            elif mutation == "other-replacement": function["change"]["actions"] = ["delete", "create"]
            elif mutation == "wrong-id": function["change"]["before"]["id"] = "other-existing-function"
            elif mutation == "old-source": function["change"]["after"]["environment"][0]["variables"]["PEASO_SOURCE_VERSION"] = "0" * 64
            elif mutation == "wrong-image":
                containers = json.loads(task["change"]["after"]["container_definitions"])
                containers[0]["image"] = deploy.ZERO_IMAGE
                task["change"]["after"]["container_definitions"] = json.dumps(containers)
            elif mutation == "size": task["change"]["after"]["memory"] = 8192
            elif mutation == "container-user":
                containers = json.loads(task["change"]["after"]["container_definitions"])
                containers[0]["user"] = "0:0"
                task["change"]["after"]["container_definitions"] = json.dumps(containers)
            elif mutation == "lambda-extra-env": function["change"]["after"]["environment"][0]["variables"]["UNREVIEWED"] = "yes"
            elif mutation == "unrelated-update":
                self.data["resource_changes"].append({"address": "aws_lambda_function.tools", "mode": "managed"})
            elif mutation == "unknown-before": task["change"]["before"] = None
            with self.subTest(mutation=mutation), self.assertRaises((RuntimeError, KeyError)):
                self.review()

    def test_baseline_artifact_and_approved_action_mutation_refused(self):
        self.baseline_path.write_text(self.baseline_path.read_text() + " ")
        with self.assertRaisesRegex(RuntimeError, "digest changed"):
            self.review()
        self.save_baseline()
        state = Path(self.baseline["state"]["path"])
        content = state.read_bytes()
        state.write_bytes(content + b" ")
        with self.assertRaisesRegex(RuntimeError, "digest changed"):
            self.review()
        state.write_bytes(content)
        self.baseline["approved_actions"]["aws_ecr_repository.worker"] = {"actions": ["update"], "reason": "source-runtime-lambda"}
        self.save_baseline()
        with self.assertRaisesRegex(RuntimeError, "unrelated address"):
            self.review()

    def test_drift_orphans_jobs_wrong_account_and_prior_state_refused(self):
        for key, value in (("drift", {"resource_drift": [{"address": "owned-drift"}]}),
                           ("orphans_and_jobs", {"account": deploy.ACCOUNT, "backend": deploy.RECOVERY_BACKEND,
                                                 "orphan_resources": ["orphan"], "active_hosted_jobs": []})):
            self.artifact(key, value)
            self.save_baseline()
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.review()

    def test_wrong_account_backend_prior_identity_and_ecr_update_refused(self):
        for key, value in (("account", "999999999999"), ("backend", dict(deploy.RECOVERY_BACKEND, key="wiki/terraform.tfstate"))):
            original = copy.deepcopy(self.baseline)
            self.baseline[key] = value
            self.save_baseline()
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, "account/backend/schema"):
                self.review()
            self.baseline = original
        self.save_baseline()
        original = copy.deepcopy(self.data)
        self.data["prior_state"]["values"]["root_module"]["resources"][0]["values"]["id"] = "other"
        with self.assertRaisesRegex(RuntimeError, "before state differs"):
            self.review()
        self.data = original
        self.data["resource_changes"][-1]["change"]["actions"] = ["update"]
        with self.assertRaisesRegex(RuntimeError, "action inventory"):
            self.review()

    def test_runtime_noop_must_be_known_and_still_match_new_source(self):
        task = self.data["resource_changes"][0]
        self.baseline["approved_actions"].pop(task["address"])
        task["change"]["after"] = copy.deepcopy(task["change"]["before"])
        task["change"]["actions"], task["change"]["after_unknown"] = ["no-op"], {}
        self.save_baseline()
        with self.assertRaisesRegex(RuntimeError, "image differs"):
            self.review()
        task["change"]["after_unknown"] = {"container_definitions": True}
        with self.assertRaisesRegex(RuntimeError, "completely known"):
            self.review()

    def test_only_frontend_terraform_may_differ(self):
        self.write_plan("iam.tf")
        with self.assertRaisesRegex(RuntimeError, "only frontend.tf"):
            self.review()

    def recorded_enrichment(self):
        task = self.data["resource_changes"][0]
        raw = self.state["resources"][0]["instances"][0]["attributes"]
        raw["tags"] = None
        task["change"]["before"]["tags"] = {}
        task["change"]["after"]["tags"] = {}
        prior = self.data["prior_state"]["values"]["root_module"]["resources"][0]
        prior["values"]["tags"] = {}
        rows = [{"address": task["address"], "mode": "managed", "type": task["type"], "name": task["name"],
                 "change": {"actions": ["update"], "before": copy.deepcopy(raw), "after": copy.deepcopy(task["change"]["before"])}}]
        self.data["resource_drift"] = rows
        self.artifact("state", self.state)
        self.artifact("drift", {"resource_drift": rows, "prior_state": self.data["prior_state"]})
        digest = self.baseline["drift"]["sha256"]
        p = patch.object(deploy, "RECOVERY_ENRICHMENT_SHA256", digest)
        p.start()
        self.addCleanup(p.stop)
        self.baseline["read_enrichment_approval"] = {"message_id": deploy.RECOVERY_ENRICHMENT_APPROVAL, "document_sha256": digest}
        self.save_baseline()

    def test_exact_recorded_enrichment_retained_and_bound_to_raw_state(self):
        self.recorded_enrichment()
        report = self.review()
        self.assertEqual(report["recovery"]["read_enrichment_approval"], self.baseline["read_enrichment_approval"])
        recovery = deploy.recovery_context(self.baseline_path, self.baseline_digest)
        self.assertNotEqual(recovery["resources"], recovery["raw_resources"])
        self.assertEqual(recovery["state"], self.state)
        self.assertEqual(recovery["drift_rows"], self.data["resource_drift"])

    def test_enrichment_document_message_rows_and_identity_tamper_refused(self):
        self.recorded_enrichment()
        original = copy.deepcopy(self.baseline)
        self.baseline["read_enrichment_approval"]["message_id"] = "other-approval"
        self.save_baseline()
        with self.assertRaisesRegex(RuntimeError, "exact supervisor-approved"):
            self.review()
        self.baseline = original
        self.save_baseline()
        self.data["resource_drift"][0]["change"]["before"]["id"] = "other-existing-task"
        with self.assertRaisesRegex(RuntimeError, "drift differs"):
            self.review()
        document = json.loads(Path(self.baseline["drift"]["path"]).read_text())
        document["timestamp"] = "changed-document"
        self.artifact("drift", document)
        self.save_baseline()
        with self.assertRaisesRegex(RuntimeError, "exact supervisor-approved"):
            self.review()

    def test_random_bytes_without_provider_id_is_known_and_immutable(self):
        attributes = {"length": 32, "hex": "ab" * 32, "base64": base64.b64encode(bytes.fromhex("ab" * 32)).decode(), "keepers": None}
        state = dict(self.state, resources=[{"mode": "managed", "type": "random_bytes", "name": "credential_key", "instances": [{"attributes": attributes}]}])
        self.assertEqual(deploy.recovery_state_resources(state)["random_bytes.credential_key"], attributes)
        attributes["base64"] = "unknown"
        with self.assertRaisesRegex(RuntimeError, "identity is unknown"):
            deploy.recovery_state_resources(state)

    def test_live_baseline_change_or_running_job_stops_before_apply(self):
        from unittest.mock import Mock
        recovery = deploy.recovery_context(self.baseline_path, self.baseline_digest)
        session = Mock()
        clients = {key: Mock() for key in ("sts", "stepfunctions", "ecs")}
        session.client.side_effect = clients.__getitem__
        clients["sts"].get_caller_identity.return_value = {"Account": deploy.ACCOUNT}
        clients["stepfunctions"].list_executions.return_value = {"executions": []}
        clients["ecs"].list_tasks.return_value = {"taskArns": []}
        def terraform(*args, **kwargs):
            return SimpleNamespace(stdout=json.dumps(self.data if args[0] == "show" else self.state))
        with patch.object(deploy, "terraform", side_effect=terraform):
            deploy.verify_recovery_live(recovery, session)
            clients["ecs"].list_tasks.return_value = {"taskArns": ["running"]}
            with self.assertRaisesRegex(RuntimeError, "active hosted ECS"):
                deploy.verify_recovery_live(recovery, session)
        mutated = dict(self.state, serial=6)
        with patch.object(deploy, "terraform", return_value=SimpleNamespace(stdout=json.dumps(mutated))), self.assertRaisesRegex(RuntimeError, "baseline changed"):
            deploy.verify_recovery_live(recovery, session)


if __name__ == "__main__":
    unittest.main()


def test_two_hour_runtime_successor_reconstructs_the_deployed_configuration():
    current = (deploy.INFRA / 'variables.tf').read_bytes()
    digest = hashlib.sha256(current).hexdigest()
    approved = {deploy.RUNTIME_LIMITS_CURRENT_SHA256}
    if hasattr(deploy, 'WORKER_SIZING_CURRENT_SHA256'):
        approved.add(deploy.WORKER_SIZING_CURRENT_SHA256)
    assert digest in approved
    restored = current
    if digest != deploy.RUNTIME_LIMITS_CURRENT_SHA256:
        for successor, predecessor in deploy.WORKER_SIZING_REVERSE:
            assert restored.count(successor) == 1
            restored = restored.replace(successor, predecessor, 1)
        assert hashlib.sha256(restored).hexdigest() == deploy.RUNTIME_LIMITS_CURRENT_SHA256
    for before, after in deploy.RUNTIME_LIMITS_EXACT_REPLACEMENTS:
        assert restored.count(after) == 1
        restored = restored.replace(after, before, 1)
    assert hashlib.sha256(restored).hexdigest() == deploy.RUNTIME_LIMITS_PREDECESSOR_SHA256
    assert deploy.RUNTIME_CONFIG_SHA256['variables.tf'] == '2824bc1ff26a1cb2bdc97109bd911d301ee1df29688253d5c2cd22236b928a58'
    assert hashlib.sha256(current + b'\n# unreviewed change\n').hexdigest() not in approved


def test_fresh_checkout_applies_explicit_operator_template_and_runtime_config(tmp_path, monkeypatch):
    package = tmp_path / 'api.zip'
    package.write_bytes(b'fixture')
    monkeypatch.setattr(deploy, 'INFRA', tmp_path)
    monkeypatch.setattr(deploy, 'BUILD', tmp_path / 'build')
    settings = {'enable_public_customer_role_template': True,
        'worker_resources': {'collector': {'cpu': 1024, 'memory': 8192},
                             'analyzer': {'cpu': 512, 'memory': 4096}},
        'scan_runtime_limits': {'collector': 7200}, 'monthly_budget_usd': 75}
    monkeypatch.setattr(deploy.deployment, 'value', lambda name: settings.get(name, ''))
    deploy.write_vars('fixture-image', package)
    variables = json.loads((tmp_path / 'deployment.auto.tfvars.json').read_text())
    for name, value in settings.items():
        assert variables[name] == value
    assert variables['worker_image'] == 'fixture-image'
