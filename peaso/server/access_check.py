"""Bounded, read-only connector access checks used before saving a connector."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
import os
import re
from threading import RLock


_COLLECTOR_IMPORT_LOCK = RLock()


def _collector_module(provider):
    # Providers publish a shared registry during import. Complete that parent
    # import once before concurrent preflights request different child modules.
    from importlib import import_module
    with _COLLECTOR_IMPORT_LOCK:
        import_module("peaso.collectors")
        return import_module("peaso.collectors." + provider)


def _probe_scopes(values, probe):
    # Independent, read-only target probes share a small bounded worker pool.
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(probe, values))


def _issue(items, severity, scope, message):
    items.append({"severity": severity, "scope": scope, "message": message})


def _expiry(value):
    if not value:
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, timezone.utc)
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
    except (ValueError, TypeError, OverflowError):
        return None


def _jwt_exp(token):
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).get("exp")
    except (IndexError, ValueError, TypeError):
        return None


def _certificate_exp(value):
    try:
        from cryptography import x509
        raw = value.encode() if isinstance(value, str) else value
        if b"-----BEGIN CERTIFICATE-----" not in raw:
            if isinstance(value, str) and os.path.isfile(value) and os.path.getsize(value) <= 1_000_000:
                with open(value, "rb") as stream:
                    raw = stream.read()
            else:
                raw = base64.b64decode(raw, validate=True)
        match = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", raw, re.DOTALL)
        return x509.load_pem_x509_certificate(match.group()).not_valid_after_utc if match else None
    except (ValueError, TypeError, AttributeError):
        return None


def _check_lifetime(auth, declared, issues):
    values = []
    if auth.get("aws_session_token"):
        values.append(("AWS session", declared))
    if auth.get("token") and not auth.get("aws_session_token"):
        values.append(("Access token", _jwt_exp(auth["token"]) or declared))
    for field in ("arm_token", "graph_token", "vault_token", "storage_token", "logs_token", "federated_token", "subject_token"):
        if auth.get(field):
            values.append((field.replace("_", " ").capitalize(), _jwt_exp(auth[field]) or declared))
    if auth.get("kubeconfig_data"):
        try:
            validate_inline_kubeconfig = _collector_module("k8s").validate_inline_kubeconfig
            configured = validate_inline_kubeconfig(auth["kubeconfig_data"], auth.get("context"))
            if configured.get("token"):
                values.append(("Kubeconfig token", _jwt_exp(configured["token"]) or declared))
        except Exception:
            pass
    for field in ("certificate_data", "client_certificate", "client_cert_data", "certificate_path", "client_cert"):
        if auth.get(field):
            expires = _certificate_exp(auth[field])
            if expires:
                values.append(("Client certificate", expires))
    for label, value in values:
        expires = _expiry(value)
        if expires is None:
            continue  # Opaque credentials must be verified through provider reads.
        if expires <= datetime.now(timezone.utc):
            _issue(issues, "critical", label, "Credential has expired. Supply a current credential.")
        elif expires < datetime.now(timezone.utc) + timedelta(hours=1):
            _issue(issues, "advisory", label, "Credential expires in less than one hour; a long scan may require renewed credentials.")


def _aws(auth, scopes, options, issues, principals):
    _session = _collector_module("aws")._session
    from botocore.config import Config
    region = (options.get("regions") or ["us-east-1"])[0]
    hosted = (auth.get("method") in {"assume_role", "task_role"}
              and str(auth.get("external_id", "")).startswith(("hacktricks-cspm-", "peaso-"))
              and not auth.get("aws_access_key_id")
              and bool(auth.get("assume_roles") or auth.get("role_arn")))
    config = Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 1})
    if hosted:
        import boto3
        from .validation import COLLECTOR_ROLE_ARN, PLATFORM_ACCOUNT_IDS
        source_session, _ = _session({"method": "default"}, region)
        collector = source_session.client("sts", config=config).assume_role(
            RoleArn=COLLECTOR_ROLE_ARN, RoleSessionName="hacktricks-cspm-access-check", DurationSeconds=3600)["Credentials"]
        session = boto3.Session(aws_access_key_id=collector["AccessKeyId"],
                                aws_secret_access_key=collector["SecretAccessKey"],
                                aws_session_token=collector["SessionToken"], region_name=region)
    else:
        source = {**auth, "method": "access_keys" if auth.get("aws_access_key_id") else auth.get("method", "default")}
        if source["method"] == "assume_role":
            source["method"] = "profile" if auth.get("profile") else "default"
        session, _ = _session(source, region)
    def assume(base, role_arn, external):
        params = {"RoleArn": role_arn, "RoleSessionName": "hacktricks-cspm-access-check", "DurationSeconds": 3600}
        if external:
            params["ExternalId"] = external
        result = base.client("sts", config=config).assume_role(**params)["Credentials"]
        import boto3
        return boto3.Session(aws_access_key_id=result["AccessKeyId"], aws_secret_access_key=result["SecretAccessKey"],
                             aws_session_token=result["SessionToken"], region_name=region)

    if not hosted:
        for step in [*(auth.get("role_chain") or []), *([{"role_arn": auth["role_arn"]}] if auth.get("role_arn") else [])]:
            entry = {"role_arn": step} if isinstance(step, str) else step
            try:
                session = assume(session, entry["role_arn"], entry.get("external_id") or auth.get("external_id"))
            except Exception:
                _issue(issues, "critical", entry.get("role_arn", "role chain"), "Could not assume the configured source role chain.")
                return
    targets = list(auth.get("assume_roles") or [])
    if hosted and auth.get("role_arn"):
        targets.append({"role_arn": auth["role_arn"]})
    if not hosted and options.get("include_source_account", True):
        targets = [{"source": True}] + targets
    if not hosted and options.get("organization_role_name"):
        token, seen = None, set()
        try:
            for _ in range(10):
                page = session.client("organizations", config=config).list_accounts(MaxResults=20, **({"NextToken": token} if token else {}))
                for account in page.get("Accounts", []):
                    ident = account.get("Id")
                    if re.fullmatch(r"[0-9]{12}", str(ident)) and account.get("State", account.get("Status")) == "ACTIVE":
                        targets.append({"role_arn": f"arn:aws:iam::{ident}:role/{options['organization_role_name']}"})
                token = page.get("NextToken")
                if not token:
                    break
                if token in seen:
                    raise ValueError("Repeated organization page")
                seen.add(token)
            if token:
                _issue(issues, "critical", "accounts", "Organization account discovery is incomplete; select account IDs explicitly.")
        except Exception:
            _issue(issues, "critical", "accounts", "Could not complete organization account discovery (organizations:ListAccounts).")
    selected_accounts = {value.split("/")[0] for value in scopes if re.match(r"^[0-9]{12}(?:/|$)", value)}
    if selected_accounts:
        targets = [target for target in targets if not (target.get("role_arn") if isinstance(target, dict) else target)
                   or (target.get("role_arn") if isinstance(target, dict) else target).split(":")[4] in selected_accounts]
    configured_accounts = {role.split(":")[4] for target in targets
                           if (role := target.get("role_arn") if isinstance(target, dict) else target)}
    if len(targets) > 100:
        _issue(issues, "critical", "accounts", "Only the first 100 target contexts can be checked; narrow the selection.")
        targets = targets[:100]
    if not targets:
        _issue(issues, "critical", "accounts", "No source account or target role is selected for scanning.")
        for account in selected_accounts:
            _issue(issues, "critical", account, "No configured identity or target role can access this selected account.")
        return sorted(selected_accounts)
    selected_accounts = {s.split("/")[0] for s in scopes if re.match(r"^[0-9]{12}(?:/|$)", s)}
    verified_accounts = set()
    attempted_accounts = set(selected_accounts) | configured_accounts
    for target in targets:
        role_arn = target.get("role_arn") if isinstance(target, dict) else target
        if hosted and role_arn and role_arn.split(":")[4] in PLATFORM_ACCOUNT_IDS:
            _issue(issues, "critical", role_arn, "Platform-owned AWS accounts cannot be role targets.")
            continue
        if role_arn and selected_accounts and role_arn.split(":")[4] not in selected_accounts:
            continue
        if role_arn and role_arn.split(":")[4] in verified_accounts:
            continue  # Match collection: one authenticated context per account.
        scope = role_arn or "source account"
        if role_arn:
            attempted_accounts.add(role_arn.split(":")[4])
        try:
            active = session
            if role_arn:
                external = (target.get("external_id") if isinstance(target, dict) else None) or auth.get("external_id")
                if hosted:
                    from peaso.auth.aws_trust import require_external_id_boundary
                    def probe(probe_external):
                        params = {"RoleArn": role_arn, "RoleSessionName": "hacktricks-cspm-access-check", "DurationSeconds": 3600}
                        if probe_external is not None:
                            params["ExternalId"] = probe_external
                        return session.client("sts", config=config).assume_role(**params)
                    try:
                        require_external_id_boundary(probe, external)
                    except Exception:
                        _issue(issues, "critical", scope, "Target role trust must reject absent and unrelated External IDs. Require an exact sts:ExternalId condition for this workspace; no account reads were performed.")
                        continue
                active = assume(session, role_arn, external)
            identity = active.client("sts", config=config).get_caller_identity()
            if hosted and identity["Account"] in PLATFORM_ACCOUNT_IDS:
                _issue(issues, "critical", scope, "Platform-owned AWS accounts cannot be scanned.")
                continue
            if not role_arn and selected_accounts and identity["Account"] not in selected_accounts:
                continue
            verified_accounts.add(identity["Account"])
            attempted_accounts.add(identity["Account"])
            principals.append({"scope": scope, "principal": identity["Arn"]})
        except Exception:
            _issue(issues, "critical", scope, "Could not authenticate or assume this target role with the configured trust and External ID.")
            continue
        from .aws_access_requirements import check_policy_requirements
        check_policy_requirements(active.client("iam", config=config), identity, scope, issues)
        try:
            active.client("iam", config=config).get_account_authorization_details(Filter=["Role"], MaxItems=1)
        except Exception:
            _issue(issues, "critical", scope, "IAM role inventory is denied (iam:GetAccountAuthorizationDetails). Grant the scanning role the documented read policies.")
        try:
            active.client("ec2", region_name=region, config=config).describe_instances(MaxResults=5)
        except Exception:
            _issue(issues, "critical", scope, "Compute inventory is denied (ec2:DescribeInstances). Grant the scanning role the documented read policies.")
        try:
            active.client("s3", config=config).list_buckets()
        except Exception:
            _issue(issues, "advisory", scope, "S3 bucket inventory is unavailable (s3:ListAllMyBuckets).")
        # Live Access Analyzer access is disabled. Saved results remain available
        # to later analysis, while a new scan records this input as unknown.
    for missing in sorted(selected_accounts - verified_accounts):
        _issue(issues, "critical", missing, "No configured identity or target role could access this selected AWS account.")
    return sorted(attempted_accounts)


def _gcp(auth, scopes, options, issues, principals, settings):
    import requests
    Credentials = _collector_module("gcp").Credentials
    from peaso.gcp_platform import PLATFORM_PROJECT, approved_project, load_service_account
    if auth.get("method") == "platform-service-account":
        if not scopes or "*" in scopes or any(options.get(key) for key in ("all_projects", "discover_projects", "all_hierarchy")):
            _issue(issues, "critical", "projects", "The shared HackTricks GCP account requires exact project IDs; discovery is unavailable.")
            return []
        auth = {"method": "service-account", "project_proof_label": auth.get("project_proof_label"),
                "sa_json": load_service_account(settings.gcp_platform_sa_secret_arn)}
    service_account = auth.get("sa_json")
    if isinstance(service_account, str):
        try:
            service_account = json.loads(service_account)
        except ValueError:
            service_account = None
    principal = service_account.get("client_email") if isinstance(service_account, dict) else auth.get("target_principal") or auth.get("impersonate_service_account") or "authenticated GCP identity"
    credentials = Credentials(auth, timeout=10)
    try:
        headers = credentials.headers()
        selected = [s.removeprefix("projects/") for s in scopes if s != "*"]
        if options.get("all_projects") or "*" in scopes:
            page_token = None
            for _ in range(10):
                response = requests.get("https://cloudresourcemanager.googleapis.com/v3/projects:search", headers=headers,
                                        params={"pageSize": 100, **({"pageToken": page_token} if page_token else {})}, timeout=10)
                response.raise_for_status()
                page = response.json()
                selected.extend(item["projectId"] for item in page.get("projects", [])
                                if item.get("projectId") and item["projectId"] != PLATFORM_PROJECT)
                page_token = page.get("nextPageToken")
                if not page_token:
                    break
            if page_token:
                _issue(issues, "critical", "projects", "Too many accessible projects to verify in one check; select project IDs explicitly.")
        selected = list(dict.fromkeys(selected))
        allowed = options.get("project_restrictions", options.get("allowed_projects"))
        if allowed is not None:
            allowed = {value.removeprefix("projects/") for value in allowed}
            selected = [value for value in selected if value in allowed]
        if not selected:
            _issue(issues, "critical", "projects", "No accessible customer project was found.")
        def probe_project(project):
            if project == PLATFORM_PROJECT:
                _issue(issues, "critical", project, "Choose a different project to scan.")
                return
            try:
                response = requests.get(f"https://cloudresourcemanager.googleapis.com/v3/projects/{project}", headers=headers, timeout=10)
                response.raise_for_status()
                item = response.json()
                if auth.get("project_proof_label") and not approved_project(item, auth["project_proof_label"]):
                    _issue(issues, "critical", project, "Project is missing this connector's approval label.")
                    return
                principals.append({"scope": project, "principal": principal})
                perms = ["resourcemanager.projects.get", "cloudasset.assets.searchAllResources",
                         "iam.roles.list", "serviceusage.services.use", "logging.logEntries.list",
                         "logging.privateLogEntries.list", "securitycenter.findings.list",
                         "recommender.iamPolicyRecommendations.list"]
                coverage = {
                    "resourcemanager.projects.get": "Project identity and metadata cannot be confirmed.",
                    "cloudasset.assets.searchAllResources": "Resource inventory may be incomplete.",
                    "iam.roles.list": "IAM role definitions and privilege findings may be incomplete.",
                    "serviceusage.services.use": "Some project APIs may refuse inventory requests.",
                    "logging.logEntries.list": "Operational and audit log evidence may be incomplete.",
                    "logging.privateLogEntries.list": "Data Access log evidence may be unavailable.",
                    "securitycenter.findings.list": "Security Command Center findings may be unavailable.",
                    "recommender.iamPolicyRecommendations.list": "IAM recommendations may be unavailable.",
                }
                response = requests.post(f"https://cloudresourcemanager.googleapis.com/v3/projects/{project}:testIamPermissions", headers=headers, json={"permissions": perms}, timeout=10)
                response.raise_for_status()
                granted = set(response.json().get("permissions", []))
                for permission in perms:
                    if permission not in granted:
                        _issue(issues, "critical" if permission in perms[:2] else "advisory", project,
                               f"Missing {permission} on this project. {coverage[permission]}")
                member_email = (service_account.get("client_email") if isinstance(service_account, dict) else
                                str(auth.get("target_principal") or auth.get("impersonate_service_account") or "")
                                .rsplit("/", 1)[-1])
                if re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", str(member_email)):
                    recommended = {
                        "roles/viewer": "Some service configuration and resource data may be missing.",
                        "roles/iam.securityReviewer": "IAM policy and role review may be incomplete.",
                        "roles/cloudasset.viewer": "Cloud Asset inventory may be incomplete.",
                        "roles/serviceusage.serviceUsageConsumer": "Some project API inventory calls may be denied.",
                        "roles/logging.privateLogViewer": "Data Access logs may be unavailable.",
                        "roles/securitycenter.findingsViewer": "Security Command Center findings may be unavailable.",
                        "roles/recommender.viewer": "IAM recommendations may be unavailable.",
                    }
                    try:
                        policy = requests.post(f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}:getIamPolicy",
                                               headers=headers, json={"options": {"requestedPolicyVersion": 3}}, timeout=10)
                        policy.raise_for_status()
                        bindings = policy.json().get("bindings", [])
                        member = "serviceAccount:" + member_email
                        direct = {binding.get("role") for binding in bindings
                                  if member in binding.get("members", []) and not binding.get("condition")}
                        for role, impact in recommended.items():
                            if role not in direct:
                                _issue(issues, "advisory", project,
                                       f"No direct unconditional {role} binding was found for {member}. It may be inherited or replaced by equivalent grants; {impact}")
                    except Exception:
                        _issue(issues, "advisory", project,
                               "Could not read project IAM bindings to compare the seven recommended roles. Effective permissions were checked, but role-based coverage remains unverified.")
                else:
                    _issue(issues, "advisory", project,
                           "Could not identify the exact IAM member to compare the seven recommended project roles. Effective permissions were checked, but direct role assignments remain unverified.")
            except Exception:
                _issue(issues, "critical", project, "Could not read this project or verify its IAM permissions.")
        _probe_scopes(selected[:100], probe_project)
        if len(selected) > 100:
            _issue(issues, "critical", "projects", "Access check supports at most 100 projects at a time; narrow the scope.")
        return selected
    finally:
        credentials.close()


def _azure(auth, scopes, issues, principals):
    provider = _collector_module("azure")
    AzureTransport, ARM, GRAPH, _claims = provider.AzureTransport, provider.ARM, provider.GRAPH, provider._claims
    transport = AzureTransport(auth)
    try:
        selected = list(dict.fromkeys(scopes))
        if not selected or "*" in selected:
            selected, url, seen = [], "https://management.azure.com/subscriptions?api-version=2022-12-01", set()
            for _ in range(10):
                if url in seen:
                    _issue(issues, "critical", "subscriptions", "Subscription discovery returned a repeated page; discovery is incomplete.")
                    break
                seen.add(url)
                response = transport.request(url)
                selected.extend(item["subscriptionId"] for item in response.get("value", []) if item.get("subscriptionId"))
                url = response.get("nextLink")
                if not url:
                    break
                from urllib.parse import urlsplit
                parsed = urlsplit(url)
                if parsed.scheme != "https" or parsed.netloc != "management.azure.com" or parsed.path != "/subscriptions" or parsed.fragment:
                    _issue(issues, "critical", "subscriptions", "Subscription discovery returned an invalid continuation; discovery is incomplete.")
                    break
            else:
                _issue(issues, "critical", "subscriptions", "Subscription discovery reached its page limit; select subscription IDs explicitly.")
            selected = list(dict.fromkeys(selected))
        if len(selected) > 100:
            _issue(issues, "critical", "subscriptions", "Only the first 100 subscriptions can be checked; narrow the selection.")
        if not selected:
            _issue(issues, "critical", "subscriptions", "No accessible Azure subscription was found.")
        def probe_subscription(value):
            subscription = value.removeprefix("/subscriptions/")
            if not re.fullmatch(r"[0-9a-fA-F-]{36}", subscription):
                _issue(issues, "critical", value, "Enter a valid subscription ID.")
                return
            try:
                transport.request(f"https://management.azure.com/subscriptions/{subscription}?api-version=2022-12-01")
                principals.append({"scope": subscription, "principal": auth.get("client_id") or "authenticated Azure identity"})
            except Exception:
                _issue(issues, "critical", subscription, "Cannot read this subscription (Microsoft.Resources/subscriptions/read).")
                return
            for resource, label, severity, impact in (
                ("resources", "resource inventory", "critical", "Subscription resources cannot be inventoried."),
                ("providers/Microsoft.Security/pricings", "Defender for Cloud", "advisory", "Security pricing and configuration evidence may be incomplete.")):
                try:
                    transport.request(f"https://management.azure.com/subscriptions/{subscription}/{resource}?api-version=" + ("2021-04-01" if resource == "resources" else "2024-01-01"))
                except Exception:
                    _issue(issues, severity, subscription, f"Cannot read {label}; check Reader and Security Reader assignments. {impact}")
            try:
                object_id = _claims(transport.token(ARM)).get("oid")
                if not object_id:
                    raise ValueError("Azure object ID unavailable")
                assignments = []
                url = f"https://management.azure.com/subscriptions/{subscription}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
                seen = set()
                for _ in range(10):
                    if url in seen:
                        raise ValueError("Repeated role-assignment page")
                    seen.add(url)
                    page = transport.request(url)
                    assignments.extend(page.get("value", []))
                    url = page.get("nextLink")
                    if not url:
                        break
                    from urllib.parse import urlsplit
                    parsed = urlsplit(url)
                    if parsed.scheme != "https" or parsed.netloc != "management.azure.com" or parsed.fragment:
                        raise ValueError("Invalid role-assignment continuation")
                else:
                    raise ValueError("Role-assignment page limit reached")
                direct = {item.get("properties", {}).get("roleDefinitionId", "").rsplit("/", 1)[-1].lower()
                          for item in assignments if item.get("properties", {}).get("principalId", "").lower() == object_id.lower()}
                for name, role_id, impact in (
                    ("Reader", "acdd72a7-3385-48ef-bd42-f606fba81ae7", "subscription resource inventory may be incomplete"),
                    ("Security Reader", "39bc4728-0917-49c7-9d2c-d95423bc2eb4", "Defender for Cloud evidence may be incomplete")):
                    if role_id not in direct:
                        _issue(issues, "advisory", subscription,
                               f"No direct {name} assignment was found for Azure object {object_id}; it may be inherited or replaced by equivalent grants, and {impact}.")
            except Exception:
                _issue(issues, "advisory", subscription,
                       "Could not read Azure role assignments for the authenticated object to compare Reader and Security Reader. Resource permissions were probed, but role-based coverage remains unverified.")
        _probe_scopes(selected[:100], probe_subscription)
        try:
            graph_token = transport.token(GRAPH)
            claims = _claims(graph_token)
            if auth.get("method") in {"client-secret", "client-cert", "workload-identity"}:
                required = {"Directory.Read.All", "Policy.Read.All", "AuditLog.Read.All", "Reports.Read.All",
                            "RoleManagement.Read.Directory", "Organization.Read.All"}
                for role in sorted(required - set(claims.get("roles", []))):
                    _issue(issues, "advisory", "Microsoft Graph", f"Missing {role} application permission or admin consent; directory, identity, policy, sign-in or report evidence may be incomplete.")
            transport.request("https://graph.microsoft.com/v1.0/organization?$top=1", audience=GRAPH)
        except Exception:
            _issue(issues, "advisory", "Microsoft Graph", "Directory inventory is unavailable. Grant the documented Graph permissions and admin consent if directory checks are needed.")
        return selected
    finally:
        if hasattr(transport, "close"):
            transport.close()


def _k8s(auth, issues, principals, scopes=()):
    from urllib.parse import quote, urlencode
    provider = _collector_module("k8s")
    if auth.get('_hosted'):
        from .k8s_access_transport import HostedAccessApi
        api = HostedAccessApi(auth)
    else:
        api = provider._new_api(auth)
    client = api.api_client
    client.rest_client.pool_manager.allow_self_subject_access_review = True
    def request(path, method="GET", body=None):
        response = client.call_api(path, method, **({"body": body} if body is not None else {}),
            auth_settings=["BearerToken"], _preload_content=False,
            _return_http_data_only=True, _request_timeout=15)
        try:
            return json.loads(response.data or response.read())
        finally:
            response.close()
            response.release_conn()
    try:
        selected = list(dict.fromkeys(scopes))
        if not selected or "*" in selected:
            selected, token, seen = [], None, set()
            for _ in range(10):
                try:
                    page = request("/api/v1/namespaces?" + urlencode({"limit": 100, **({"continue": token} if token else {})}))
                    selected.extend(item["metadata"]["name"] for item in page.get("items", []) if item.get("metadata", {}).get("name"))
                    token = page.get("metadata", {}).get("continue")
                    if not token:
                        break
                    if token in seen:
                        raise ValueError("Repeated namespace page")
                    seen.add(token)
                except Exception:
                    _issue(issues, "critical", "namespace discovery", "Could not complete namespace discovery; grant permission to list namespaces or select namespaces explicitly.")
                    break
            else:
                _issue(issues, "critical", "namespace discovery", "Namespace discovery reached its page limit; select namespaces explicitly.")
        selected = list(dict.fromkeys(selected))
        if not selected:
            _issue(issues, "critical", "namespace discovery", "No namespace was found for this selection.")
        if len(selected) > 100:
            _issue(issues, "critical", "namespace discovery", "Only the first 100 namespaces can be checked; narrow the selection.")
        def probe_namespace(namespace):
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", namespace):
                _issue(issues, "critical", namespace, "Enter a valid namespace name.")
                return
            try:
                request("/api/v1/namespaces/" + quote(namespace, safe=""))
                principals.append({"scope": namespace, "principal": "authenticated Kubernetes identity"})
            except Exception:
                _issue(issues, "critical", namespace, "Cannot read this namespace.")
                return
            for group, resource, severity, impact in (
                    ("", "pods", "critical", "Pod and workload evidence"),
                    ("apps", "deployments", "critical", "Deployment configuration evidence"),
                    ("rbac.authorization.k8s.io", "roles", "critical", "Namespace RBAC rule evidence"),
                    ("rbac.authorization.k8s.io", "rolebindings", "critical", "Namespace RBAC binding evidence"),
                    ("", "serviceaccounts", "advisory", "Service account identity evidence"),
                    ("", "services", "advisory", "Service network evidence"),
                    ("", "configmaps", "advisory", "ConfigMap configuration evidence"),
                    ("batch", "jobs", "advisory", "Job workload evidence"),
                    ("networking.k8s.io", "networkpolicies", "advisory", "Network policy evidence"),
                    ("", "secrets", "advisory", "Secret metadata evidence")):
                review = {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
                    "spec": {"resourceAttributes": {"namespace": namespace, "group": group, "resource": resource, "verb": "list"}}}
                try:
                    result = request("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "POST", review)
                    if result.get("status", {}).get("allowed") is not True:
                        _issue(issues, severity, namespace, f"Cannot list {resource} in this namespace; {impact} may be unavailable.")
                except Exception:
                    _issue(issues, severity, namespace, f"Could not verify list access to {resource} in this namespace; {impact} may be unavailable.")
        _probe_scopes(selected[:100], probe_namespace)
        for group, resource, impact in (
                ("rbac.authorization.k8s.io", "clusterroles", "Cluster RBAC rule evidence"),
                ("rbac.authorization.k8s.io", "clusterrolebindings", "Cluster RBAC binding evidence"),
                ("", "nodes", "Node configuration evidence"),
                ("", "persistentvolumes", "Persistent volume evidence"),
                ("storage.k8s.io", "storageclasses", "Storage class evidence"),
                ("admissionregistration.k8s.io", "validatingwebhookconfigurations", "Admission webhook evidence"),
                ("admissionregistration.k8s.io", "mutatingwebhookconfigurations", "Admission webhook evidence")):
            review = {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
                "spec": {"resourceAttributes": {"group": group, "resource": resource, "verb": "list"}}}
            try:
                if request("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "POST", review).get("status", {}).get("allowed") is not True:
                    _issue(issues, "advisory", "cluster RBAC", f"Cannot list {resource}; {impact} may be unavailable.")
            except Exception:
                _issue(issues, "advisory", "cluster RBAC", f"Could not verify list access to {resource}; {impact} may be unavailable.")
        return selected
    finally:
        if hasattr(api, "close"):
            api.close()


def _scope_report(provider, selected, issues, principals):
    units = {"aws": "accounts", "gcp": "projects", "azure": "subscriptions", "k8s": "namespaces"}
    def normalized(value):
        if not isinstance(value, str) or value == "*":
            return None
        if provider == "aws":
            match = re.search(r"(?<!\d)(\d{12})(?!\d)", value)
            return match[1] if match else None
        if provider == "azure":
            value = value.removeprefix("/subscriptions/")
            return value.lower() if re.fullmatch(r"[0-9a-fA-F-]{36}", value) else None
        if provider == "gcp":
            value = value.removeprefix("projects/")
            return value if value != "projects" and re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", value) else None
        return value if re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value) else None
    rows = {}
    def row(scope):
        return rows.setdefault(scope, {"scope": scope, "principals": [], "issues": [], "status": "not_checked"})
    for value in selected:
        scope = normalized(value)
        if scope:
            row(scope)
    aliases = {}
    for principal in principals:
        scope = normalized(principal["scope"]) or (normalized(principal["principal"]) if provider == "aws" else None)
        if scope:
            aliases[principal["scope"]] = scope
            if principal["principal"] not in row(scope)["principals"]:
                row(scope)["principals"].append(principal["principal"])
    for item in issues:
        scope = aliases.get(item["scope"]) or normalized(item["scope"])
        if scope in rows:
            row(scope)["issues"].append(item)
    for value in rows.values():
        value["status"] = ("blocked" if any(item["severity"] == "critical" for item in value["issues"]) else
                           "warning" if value["issues"] else "pass" if value["principals"] else "not_checked")
    return {"scope_summary": {"unit": units[provider], "total": len(rows),
                "accessible": sum(bool(value["principals"]) for value in rows.values()),
                "blocked": sum(value["status"] == "blocked" for value in rows.values()),
                "warning": sum(value["status"] == "warning" for value in rows.values()),
                "not_checked": sum(value["status"] == "not_checked" for value in rows.values())},
            "scope_results": list(rows.values())}

def check_access(provider, auth, scopes, options, settings, *, credential_expires_at=None):
    issues, principals = [], []
    if provider == 'k8s' and settings.auth_mode == 'cognito':
        auth = dict(auth, _hosted=True)
    selected = [scope for scope in scopes if scope != "*"]
    _check_lifetime(auth, credential_expires_at, issues)
    if not any(item["severity"] == "critical" for item in issues):
        try:
            discovered = {"aws": _aws, "gcp": _gcp, "azure": _azure, "k8s": _k8s}[provider](
                *((auth, scopes, options, issues, principals) if provider == "aws" else
                  (auth, scopes, options, issues, principals, settings) if provider == "gcp" else
                  (auth, scopes, issues, principals) if provider == "azure" else
                  (auth, issues, principals, scopes)))
            if discovered is not None:
                selected = discovered
        except Exception as exc:
            status = getattr(exc, "status", None)
            suffix = f" (HTTP {status})" if isinstance(status, int) and 100 <= status <= 599 else ""
            _issue(issues, "critical", provider, "Could not authenticate or complete the access check" + suffix + ". Verify the credential, endpoint and target scope.")
    issues.sort(key=lambda item: (item["scope"], item["severity"], item["message"]))
    principals.sort(key=lambda item: (item["scope"], item["principal"]))
    status = "blocked" if any(item["severity"] == "critical" for item in issues) else "warning" if issues else "pass"
    return {"status": status, "issues": issues, "principals": principals,
            "requires_warning_acknowledgement": status == "warning",
            **_scope_report(provider, selected, issues, principals)}
