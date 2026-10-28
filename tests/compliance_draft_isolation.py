"""Explicit test-only boundary for unpublished native check modules."""

from __future__ import annotations

import ast
import hashlib
from contextlib import contextmanager
import sys
from functools import lru_cache
from pathlib import Path

import peaso.checks  # Establish the published runtime module boundary before test collection.


# Each named test imports its corresponding unpublished module at collection.
# Review additions here before they can enter an ordinary full-suite process.
DRAFT_TEST_MODULES = {
    "test_peaso_compliance_new_gcp_gke.py": "compliance_new_gcp_gke",
    "test_peaso_compliance_new_k8s_component_pid_projection.py": "compliance_new_k8s_component",
    "test_peaso_checks_aws_a_cloudtrail_presence.py": "aws_a_cloudtrail_presence",
    "test_peaso_checks_aws_a_ec2.py": "aws_a_ec2",
    "test_peaso_checks_aws_a_remaining.py": "aws_a_remaining",
    "test_peaso_checks_aws_a_sharing.py": "aws_a_sharing",
    "test_peaso_checks_azure_ports_app.py": "azure_ports_app",
    "test_peaso_checks_azure_ports_app_variants.py": "azure_ports_app_variants",
    "test_peaso_checks_azure_ports_compute.py": "azure_ports_compute",
    "test_peaso_checks_azure_ports_directory_extra.py": "azure_ports_directory_extra",
    "test_peaso_checks_azure_ports_flexible.py": "azure_ports_flexible",
    "test_peaso_checks_azure_ports_iam.py": "azure_ports_iam",
    "test_peaso_checks_azure_ports_misc.py": "azure_ports_misc",
    "test_peaso_checks_azure_ports_monitor_extra.py": "azure_ports_monitor_extra",
    "test_peaso_checks_azure_ports_network.py": "azure_ports_network",
    "test_peaso_checks_azure_ports_sql.py": "azure_ports_sql",
    "test_peaso_checks_azure_ports_storage_extra.py": "azure_ports_storage_extra",
    "test_peaso_checks_azure_ports_tail.py": "azure_ports_tail",
    "test_peaso_checks_azure_ports_tail_context.py": "azure_ports_tail_context",
    "test_peaso_checks_k8s_ports_rbac_signals.py": "k8s_ports_rbac_signals",
}
# Staged SW fixtures are unselected in ordinary full-suite collection. Every
# filename and direct registrar import is pinned; none joins the 20 child proxies.
STAGED_UNSELECTED_TEST_MODULES = {
    'test_peaso_azure_assessment_sw17_staged.py': ('compliance_new_sw17',),
    'test_peaso_literal_policy_coverage_next.py': ('compliance_new_sw12',),
    'test_peaso_collector_swc_azure.py': ('compliance_new_sw01', 'compliance_new_sw02', 'compliance_new_sw03', 'compliance_new_sw04'),
    'test_peaso_collector_swc_k8s.py': ('compliance_new_sw10',),
    'test_peaso_compliance_new_sw01.py': ('compliance_new_sw01',),
    'test_peaso_compliance_new_sw02.py': ('compliance_new_sw02',),
    'test_peaso_compliance_new_sw04.py': ('compliance_new_sw04',),
    'test_peaso_compliance_new_sw05.py': ('compliance_new_sw05', 'compliance_new_sw06', 'compliance_new_sw07'),
    'test_peaso_compliance_new_sw06.py': ('compliance_new_sw06',),
    'test_peaso_compliance_new_sw07.py': ('compliance_new_sw07',),
    'test_peaso_compliance_new_sw08.py': ('compliance_new_sw08',),
    'test_peaso_compliance_new_sw09.py': ('compliance_new_sw09',),
    'test_peaso_compliance_new_sw10.py': ('compliance_new_sw10',),
    'test_peaso_compliance_new_sw15.py': ('compliance_new_sw15',),
    'test_peaso_compliance_new_sw17.py': ('compliance_new_sw17',),
    'test_peaso_compliance_new_sw21.py': ('compliance_new_sw21',),
    'test_peaso_compliance_new_sw22.py': ('compliance_new_sw22',),
    'test_peaso_compliance_new_sw24.py': ('compliance_new_sw24',),
    'test_peaso_compliance_new_sw25.py': ('compliance_new_sw25',),
    'test_peaso_compliance_new_sw26.py': ('compliance_new_sw26',),
    'test_peaso_compliance_new_sw27.py': ('compliance_new_sw27',),
    'test_peaso_compliance_new_sw28.py': ('compliance_new_sw28',),
    'test_peaso_compliance_new_sw29.py': ('compliance_new_sw29',),
    'test_peaso_compliance_new_sw30.py': ('compliance_new_sw30',),
    'test_peaso_compliance_new_sw31.py': ('compliance_new_sw31',),
    'test_peaso_compliance_new_sw32.py': ('compliance_new_sw32',),
    'test_peaso_compliance_new_sw33.py': ('compliance_new_sw33',),
    'test_peaso_compliance_new_sw34.py': ('compliance_new_sw34',),
    'test_peaso_compliance_new_sw35.py': ('compliance_new_sw35',),
    # Reads the admitted bulk module and removes its IDs during teardown;
    # it must remain excluded from ordinary collection despite importing no draft.
    'test_peaso_compliance_new_sw36.py': (),
    'test_peaso_compliance_new_sw37.py': ('compliance_new_sw37',),
    'test_peaso_compliance_new_sw38.py': ('compliance_new_sw38',),
    'test_peaso_compliance_new_sw39.py': ('compliance_new_sw39',),
    'test_peaso_compliance_new_sw40_iam.py': ('compliance_new_sw40',),
    'test_peaso_compliance_new_sw40_kms.py': ('compliance_new_sw40',),
    'test_peaso_compliance_new_sw41.py': ('compliance_new_sw41',),
    'test_peaso_compliance_new_sw42.py': ('compliance_new_sw42',),
    # Like sw36, this fixture uses admitted bulk evaluators and tears them down.
    'test_peaso_compliance_new_sw43.py': (),
    'test_peaso_compliance_new_sw44.py': ('compliance_new_sw44',),
    'test_peaso_compliance_new_sw45.py': ('compliance_new_sw45',),
    'test_peaso_compliance_new_sw46.py': ('compliance_new_sw46',),
    'test_peaso_compliance_new_sw47.py': ('compliance_new_sw47',),
    # This legacy fixture reads a preloaded bulk module from sys.modules and
    # requires its own --noconftest process; keep it out of ordinary collection.
    'test_peaso_compliance_new_sw48.py': (),
    'test_peaso_compliance_new_sw49.py': ('compliance_new_sw49',),
    'test_peaso_compliance_new_sw50.py': ('compliance_new_sw50',),
    'test_peaso_compliance_new_sw51.py': ('compliance_new_sw51',),
    'test_peaso_compliance_new_sw52.py': ('compliance_new_sw52',),
    'test_peaso_compliance_new_sw53.py': ('compliance_new_sw53',),
    'test_peaso_compliance_new_sw54.py': ('compliance_new_sw54',),
    'test_peaso_compliance_new_sw55.py': ('compliance_new_sw55',),
    'test_peaso_compliance_new_sw56.py': ('compliance_new_sw56',),
    'test_peaso_compliance_new_sw57.py': ('compliance_new_sw57',),
}

# These tests also import registrar modules dynamically; isolate them exactly
# like the direct-import wave tests now that their IDs are in the bulk runtime.
STAGED_UNSELECTED_TEST_MODULES.update({
    # Native checks held from this release retain exact, directed proof only.
    "test_peaso_aws_resolver_logging_state.py": ("aws_resolver_delivery_ready",),
    "test_peaso_aws_resolver_delivery_ready_public_collect.py": ("aws_resolver_delivery_ready",),
    "test_peaso_aws_resource_tag_compliance_native.py": ("aws_resource_tag_compliance",),
    "test_peaso_aws_effective_tag_policy_contract.py": ("aws_effective_tag_policy",),
    "test_peaso_aws_effective_tag_policy_public_collect.py": ("aws_effective_tag_policy",),
    "test_peaso_antimalware_extension_native_route.py": ("azure_antimalware_extension_native",),
    "test_peaso_compliance_new_sw03.py": ("compliance_new_sw03",),
    "test_peaso_compliance_new_sw11.py": ("compliance_new_sw11",),
    "test_peaso_compliance_new_sw12.py": ("compliance_new_sw12",),
    "test_peaso_compliance_new_sw13.py": ("compliance_new_sw13",),
    "test_peaso_compliance_new_sw14.py": ("compliance_new_sw14",),
    "test_peaso_compliance_new_sw16.py": ("compliance_new_sw16",),
    "test_peaso_compliance_new_sw18.py": ("compliance_new_sw18",),
    "test_peaso_compliance_new_sw19.py": ("compliance_new_sw19",),
    "test_peaso_compliance_new_sw20.py": ("compliance_new_sw20",),
    "test_peaso_compliance_new_sw23.py": ("compliance_new_sw23",),
})

PUBLISHED_MODULES = frozenset({
    "compliance_new_aws", "compliance_new_aws_apigateway", "compliance_new_aws_inspector_ec2", "compliance_new_azure", "compliance_new_gcp", "compliance_new_gcp_api_keys", "compliance_new_k8s",
})
CHILD_FILE_ENV = "PEASO_COMPLIANCE_DRAFT_CHILD_FILE"
INACTIVE_REGISTRAR_MODULES = frozenset(DRAFT_TEST_MODULES.values())
PUBLISHED_CHECK_MODULES = frozenset(name.rsplit(".", 1)[-1] for name in sys.modules
                                    if name.startswith("peaso.checks."))
# A successor can replace an initializer import without loading its immutable
# historical admission helper. Permit only this reviewed predecessor, and only
# when its exact successor was admitted at runtime startup. Pin the historical
# source to the predecessor digest in that successor's reviewed receipt.
PUBLISHED_HISTORICAL_SUCCESSORS = {
    "azure_nsp_query_cmk_production_admission_20261020": (
        "azure_nsp_query_cmk_production_tde_successor_20261020",
        "1b76f9b3d5e496bde5c0d0051aadbca85ade023982edffa47c1bddc8cb2b3805",
    ),
}
CHECKS_DIR = Path(__file__).resolve().parents[1] / "peaso" / "checks"


@contextmanager
def staged_registry(modules):
    """Let an explicitly selected draft replace runtime overlaps in this process.

    Only the named staged modules can replace original runtime registrations.
    Duplicate registrations within the draft still fail through the real guard.
    The original objects, aliases and register function are restored on exit.
    """
    modules = tuple(modules)
    registry = peaso.checks
    original = tuple(registry.CHECKS)
    original_objects = {id(check) for check in original}
    aliases = dict(registry.CHECK_ALIASES)
    register = registry.register
    permitted = {"peaso.checks." + name for name in modules}
    absent = object()
    prior_modules = {name: sys.modules.get(name, absent) for name in permitted}
    prior_attributes = {name: registry.__dict__.get(name, absent) for name in modules}

    def isolated_register(check_id, *args, **kwargs):
        decorate = register(check_id, *args, **kwargs)

        def isolated_decorate(function):
            if function.__module__ in permitted:
                registry.CHECKS[:] = [check for check in registry.CHECKS
                                     if check.id != check_id or id(check) not in original_objects]
                if check_id in aliases:
                    registry.CHECK_ALIASES.pop(check_id, None)
            return decorate(function)

        return isolated_decorate

    registry.register = isolated_register
    try:
        yield
    finally:
        registry.register = register
        registry.CHECKS[:] = original
        registry.CHECK_ALIASES.clear()
        registry.CHECK_ALIASES.update(aliases)
        # An isolated fixture can retain evaluator closures, but its registrar
        # must not remain importable from the ordinary parent test process.
        for name, previous in prior_modules.items():
            if previous is absent:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
        for name, previous in prior_attributes.items():
            if previous is absent:
                registry.__dict__.pop(name, None)
            else:
                registry.__dict__[name] = previous


@lru_cache(maxsize=None)
def _unpublished_module(name: str) -> bool:
    if name in INACTIVE_REGISTRAR_MODULES:
        return True
    if name in PUBLISHED_CHECK_MODULES or name in PUBLISHED_MODULES:
        return False
    if name in PUBLISHED_HISTORICAL_SUCCESSORS:
        successor, digest = PUBLISHED_HISTORICAL_SUCCESSORS[name]
        source = CHECKS_DIR / (name + ".py")
        return not (successor in PUBLISHED_CHECK_MODULES and source.is_file()
                    and hashlib.sha256(source.read_bytes()).hexdigest() == digest)
    if name.startswith("compliance_new_"):
        return True
    source = CHECKS_DIR / (name + ".py")
    if not source.is_file():
        return False
    tree = ast.parse(source.read_text())
    return any(isinstance(node, ast.Call) and
               (isinstance(node.func, ast.Name) and node.func.id == "register" or
                isinstance(node.func, ast.Attribute) and node.func.attr == "register")
               for node in ast.walk(tree))


def unpublished_check_imports(path: Path) -> set[str]:
    """Inspect direct import syntax at any depth; never import the target test."""
    imported = set()
    tree = ast.parse(path.read_text())
    literals = {node.targets[0].id: node.value.value for node in ast.walk(tree)
                if isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'import_module' and node.args:
            arg = node.args[0]
            name = arg.value if isinstance(arg, ast.Constant) else literals.get(arg.id) if isinstance(arg, ast.Name) else None
            if isinstance(name, str) and name.startswith('peaso.checks.') and _unpublished_module(name.rsplit('.', 1)[-1]):
                imported.add(name.rsplit('.', 1)[-1])
        if isinstance(node, ast.ImportFrom) and node.module == "peaso.checks":
            imported.update(alias.name for alias in node.names if _unpublished_module(alias.name))
        elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith("peaso.checks."):
            name = node.module.rsplit(".", 1)[-1]
            if _unpublished_module(name):
                imported.add(name)
        elif isinstance(node, ast.Import):
            imported.update(alias.name.rsplit(".", 1)[-1] for alias in node.names
                            if alias.name.startswith("peaso.checks.")
                            and _unpublished_module(alias.name.rsplit(".", 1)[-1]))
    return imported


def staged_modules_unregistered(modules) -> bool:
    """Prove staged registrars were absent at startup and remain unregistered."""
    named = set(modules)
    registered = {check.evaluate.__module__.rsplit(".", 1)[-1] for check in peaso.checks.CHECKS}
    return not named.intersection(PUBLISHED_CHECK_MODULES | registered)
