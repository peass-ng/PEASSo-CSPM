"""claude2_aws_b edge service group: native ports plus merged, manual and rejected rows.

CloudFront, Classic ELB, ELBv2, API Gateway (REST and v2), AppSync and Direct Connect.
Every predicate reads the documented AWS API response shape; facts the collector does not
gather yet are listed in COLLECTOR_FACTS and evaluate to UNKNOWN until they are collected.
"""
from __future__ import annotations

from .claude2_aws_b_common import (P, C, X, install, result, unknown, get, optional, list_of_objects, complete_items,
                                   Unavailable, strings, absent_or, parse_time, scope_of, inventory, indexes, sg_rule_open,
                                   security_groups, turbot_public_statements, policy_document, detail, detail_list,
                                   days_between, ABSENT, SCOPE, ACCOUNT)

ANCHOR = {"scope": SCOPE}

D_CF = "https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_DistributionConfig.html"
D_CF_ORIGIN = "https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_Origin.html"
D_CF_S3 = "https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_S3OriginConfig.html"
D_CF_VC = "https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ViewerCertificate.html"
D_CF_TLS = "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html"
D_CF_OAC = "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html"
D_CF_LOG = "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/standard-logging.html"
D_LOGS = "https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DescribeDeliveries.html"
D_HEAD = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html"
D_LB = "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_LoadBalancer.html"
D_LISTENER = "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_Listener.html"
D_RULES = "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeRules.html"
D_REDIRECT = "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RedirectActionConfig.html"
D_LB_ATTR = "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_LoadBalancerAttribute.html"
D_ALB_POL = "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html"
D_NLB_POL = "https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html"
D_CLB = "https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_LoadBalancerDescription.html"
D_CLB_POL = "https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html"
D_SG = "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_SecurityGroup.html"
D_ACM = "https://docs.aws.amazon.com/acm/latest/APIReference/API_CertificateDetail.html"
D_IAM_CERT = "https://docs.aws.amazon.com/IAM/latest/APIReference/API_ServerCertificateMetadata.html"
D_WAFV2 = "https://docs.aws.amazon.com/waf/latest/APIReference/API_ListResourcesForWebACL.html"
D_WAFR = "https://docs.aws.amazon.com/waf/latest/APIReference/API_wafRegional_ListResourcesForWebACL.html"
D_STAGE = "https://docs.aws.amazon.com/apigateway/latest/api/API_Stage.html"
D_METHOD_SETTING = "https://docs.aws.amazon.com/apigateway/latest/api/API_MethodSetting.html"
D_REST = "https://docs.aws.amazon.com/apigateway/latest/api/API_RestApi.html"
D_AUTHORIZER = "https://docs.aws.amazon.com/apigateway/latest/api/API_Authorizer.html"
D_METHOD = "https://docs.aws.amazon.com/apigateway/latest/api/API_Method.html"
D_DOMAIN = "https://docs.aws.amazon.com/apigateway/latest/api/API_DomainName.html"
D_APIGW_TLS = "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-security-policies-list.html"
D_V2_ROUTE = "https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-routes.html"
D_V2_AUTH = "https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-authorizers.html"
D_APPSYNC = "https://docs.aws.amazon.com/appsync/latest/APIReference/API_GraphqlApi.html"
D_APPSYNC_CACHE = "https://docs.aws.amazon.com/appsync/latest/APIReference/API_ApiCache.html"
D_DX_CONN = "https://docs.aws.amazon.com/directconnect/latest/APIReference/API_Connection.html"
D_DX_VIF = "https://docs.aws.amazon.com/directconnect/latest/APIReference/API_VirtualInterface.html"
D_DX_RES = "https://docs.aws.amazon.com/directconnect/latest/UserGuide/resiliency_toolkit.html"

# Collector facts these predicates read that the AWS collector does not gather yet (read-only APIs only).
COLLECTOR_FACTS = [
    {"kind": "cloudfront_distribution", "api": "logs:DescribeDeliverySources + logs:DescribeDeliveries (us-east-1)",
     "fields": ["LogDeliveries.deliveries[].deliverySourceName (sources whose resourceArns contain the distribution ARN)"],
     "checks": ["aws.c2b.cloudfront.logging_any"]},
    {"kind": "cloudfront_distribution", "api": "s3:HeadBucket (origin buckets absent from the account bucket inventory)",
     "fields": ["OriginBucketProbes.results[].Bucket", "OriginBucketProbes.results[].HttpStatusCode"],
     "checks": ["aws.c2b.cloudfront.s3_origin_bucket_exists"]},
    {"kind": "load_balancer", "api": "elbv2:DescribeRules(ListenerArn) for HTTP listeners",
     "fields": ["Listeners.items[].DefaultActions[].Type", "Listeners.items[].DefaultActions[].RedirectConfig.Protocol",
                "Listeners.items[].Rules.collection_status", "Listeners.items[].Rules.items[].IsDefault",
                "Listeners.items[].Rules.items[].Actions[].Type", "Listeners.items[].Rules.items[].Actions[].RedirectConfig.Protocol"],
     "checks": ["aws.c2b.elbv2.http_listeners_redirect_https"]},
    {"kind": "wafv2_web_acl", "api": "wafv2:ListWebACLs(Scope=REGIONAL) + wafv2:ListResourcesForWebACL(ResourceType=APPLICATION_LOAD_BALANCER)",
     "fields": ["ARN", "ResourceArns.ResourceArns"], "checks": ["aws.c2b.elbv2.alb_waf_attached", "aws.c2b.elbv2.alb_wafv2_attached"]},
    {"kind": "wafregional_web_acl", "api": "waf-regional:ListWebACLs + waf-regional:ListResourcesForWebACL(ResourceType=APPLICATION_LOAD_BALANCER)",
     "fields": ["WebACLId", "ResourceArns.ResourceArns"], "checks": ["aws.c2b.elbv2.alb_waf_attached"]},
    {"kind": "apigateway_domain_name", "api": "apigateway:GetDomainNames",
     "fields": ["domainName", "securityPolicy", "endpointConfiguration.types"], "checks": ["aws.c2b.apigateway.domain_pqc_tls"]},
    {"kind": "rest_api", "api": "apigateway:GetAuthorizers(restApiId)", "fields": ["Authorizers.items[].id", "Authorizers.items[].type"],
     "checks": ["aws.c2b.apigateway.authorizers_or_authorized_methods", "aws.c2b.apigateway.public_rest_api_authorizer",
                "aws.c2b.apigateway.rest_api_has_authorizer"]},
    {"kind": "rest_api", "api": "apigateway:GetResources(restApiId, embed=methods)",
     "fields": ["Resources.items[].path", "Resources.items[].resourceMethods.<verb>.authorizationType",
                "Resources.items[].resourceMethods.<verb>.requestValidatorId"],
     "checks": ["aws.c2b.apigateway.authorizers_or_authorized_methods", "aws.c2b.apigateway.methods_authorization_type",
                "aws.c2b.apigateway.methods_request_validator"]},
    {"kind": "http_api", "api": "apigatewayv2:GetAuthorizers(ApiId)", "fields": ["Authorizers.items[].AuthorizerId"],
     "checks": ["aws.c2b.apigatewayv2.api_has_authorizer"]},
    {"kind": "http_api", "api": "apigatewayv2:GetRoutes(ApiId)",
     "fields": ["Routes.items[].RouteId", "Routes.items[].AuthorizationType", "Routes.items[].AuthorizerId"],
     "checks": ["aws.c2b.apigatewayv2.routes_authorization_type", "aws.c2b.apigatewayv2.routes_authorizer"]},
    {"kind": "appsync_graphql_api", "api": "appsync:ListGraphqlApis + appsync:GetApiCache(apiId)",
     "fields": ["apiId", "apiType", "authenticationType", "logConfig.fieldLogLevel", "ApiCache.apiCache.atRestEncryptionEnabled",
                "ApiCache.apiCache.transitEncryptionEnabled"],
     "checks": ["aws.c2b.appsync.field_level_logging", "aws.c2b.appsync.graphql_no_api_key", "aws.c2b.appsync.no_api_key_auth",
                "aws.c2b.appsync.cache_at_rest_encryption", "aws.c2b.appsync.cache_in_transit_encryption"]},
    {"kind": "directconnect_connection", "api": "directconnect:DescribeConnections", "fields": ["connectionId", "location"],
     "checks": ["aws.c2b.directconnect.connection_redundancy"]},
    {"kind": "directconnect_virtual_interface", "api": "directconnect:DescribeVirtualInterfaces",
     "fields": ["virtualInterfaceId", "connectionId", "virtualGatewayId", "directConnectGatewayId"],
     "checks": ["aws.c2b.directconnect.virtual_interface_redundancy"]},
]


# =========================================================================== CloudFront
CF_ARN = "arn:aws:cloudfront::" + ACCOUNT + ":distribution/E1"
VIEWER = ("allow-all", "https-only", "redirect-to-https")
# steampipe-mod-aws-compliance variable cloudfront_distribution_tls_security_policy (pinned default)
CF_RECOMMENDED_TLS = ["TLSv1.2_2021"]
# prowler PQC_CLOUDFRONT_POLICIES_DEFAULT
CF_PQC = ["TLSv1.3_2025"]
DEPRECATED_ORIGIN_SSL = ("SSLv3", "TLSv1", "TLSv1.1")


def _cf(**config):
    return {"ARN": CF_ARN, "Id": "E1", "Config": {"DistributionConfig": {"CallerReference": "r", **config}}}


def _origins_of(*rows):
    return {"Quantity": len(rows), "Items": list(rows)}


def _s3o(oid="s3", bucket="site", oai="", oac=""):
    row = {"Id": oid, "DomainName": bucket + ".s3.amazonaws.com", "S3OriginConfig": {"OriginAccessIdentity": oai}}
    if oac:
        row["OriginAccessControlId"] = oac
    return row


def _custom(oid="web", policy="https-only", protocols=("TLSv1.2",)):
    return {"Id": oid, "DomainName": "app.example.com", "OriginAccessControlId": "",
            "CustomOriginConfig": {"OriginProtocolPolicy": policy, "OriginSslProtocols": {"Quantity": len(protocols), "Items": list(protocols)}}}


def _cfg(item):
    data = get(item, "Config.DistributionConfig", dict)
    get(data, "CallerReference", str)
    return data


def _origins(data):
    origins = get(data, "Origins", dict)
    rows = list_of_objects(get(origins, "Items", list))
    if get(origins, "Quantity", int) != len(rows):
        raise Unavailable("origin quantity does not match the origin list")
    return rows


def _s3_config(origin):
    return optional(origin, "S3OriginConfig", {}, dict)


def _viewer_policy(data):
    policy = get(data, "DefaultCacheBehavior.ViewerProtocolPolicy", str)
    if policy not in VIEWER:
        raise Unavailable("unrecognized viewer protocol policy")
    return policy


@install("aws.c2b.cloudfront.custom_ssl_certificate", "cloudfront_distribution", "CloudFront distribution does not use the default CloudFront certificate",
         _cf(ViewerCertificate={"CloudFrontDefaultCertificate": False, "ACMCertificateArn": "arn:aws:acm:us-east-1:" + ACCOUNT + ":certificate/c1", "SSLSupportMethod": "sni-only"}),
         _cf(ViewerCertificate={"CloudFrontDefaultCertificate": True, "MinimumProtocolVersion": "TLSv1"}),
         rows=[P + "cloudfront_distributions_custom_ssl_certificate"], severity="medium", control="SC-8",
         remediation="Attach a custom ACM (us-east-1) or IAM certificate for the distribution's alternate domain names instead of the default *.cloudfront.net certificate.",
         docs=[D_CF_VC])
def cf_custom_certificate(item, index):
    default = get(_cfg(item), "ViewerCertificate.CloudFrontDefaultCertificate", bool)
    return result(default, cloudfront_default_certificate=default)


@install("aws.c2b.cloudfront.default_behavior_https", "cloudfront_distribution", "CloudFront default cache behavior redirects to or requires HTTPS",
         _cf(DefaultCacheBehavior={"ViewerProtocolPolicy": "redirect-to-https"}), _cf(DefaultCacheBehavior={"ViewerProtocolPolicy": "allow-all"}),
         rows=[P + "cloudfront_distributions_https_enabled"], severity="medium", control="SC-8",
         remediation="Set the default cache behavior ViewerProtocolPolicy to redirect-to-https or https-only.", docs=[D_CF],
         extra={"https_only_pass": _cf(DefaultCacheBehavior={"ViewerProtocolPolicy": "https-only"})},
         note="Prowler evaluates the default cache behavior only; aws.b.cloudfront.viewer_encryption covers every additional behavior.")
def cf_default_https(item, index):
    policy = _viewer_policy(_cfg(item))
    return result(policy == "allow-all", viewer_protocol_policy=policy)


@install("aws.c2b.cloudfront.https_sni", "cloudfront_distribution", "CloudFront distribution with a custom certificate serves HTTPS via SNI only",
         _cf(ViewerCertificate={"Certificate": "arn:aws:acm:us-east-1:" + ACCOUNT + ":certificate/c1", "CertificateSource": "acm", "SSLSupportMethod": "sni-only"}),
         _cf(ViewerCertificate={"Certificate": "arn:aws:acm:us-east-1:" + ACCOUNT + ":certificate/c1", "CertificateSource": "acm", "SSLSupportMethod": "vip"}),
         rows=[P + "cloudfront_distributions_https_sni_enabled"], severity="low",
         remediation="Set ViewerCertificate.SSLSupportMethod to sni-only (dedicated-IP 'vip' is only needed for legacy clients without SNI).",
         docs=[D_CF_VC], extra={"not_applicable": _cf(ViewerCertificate={"CloudFrontDefaultCertificate": True}),
                                "no_method": _cf(ViewerCertificate={"Certificate": "arn:aws:iam::" + ACCOUNT + ":server-certificate/c", "CertificateSource": "iam"}),
                                "no_method_expect": "FAIL"},
         note="Applies only when ViewerCertificate.Certificate is set; an omitted SSLSupportMethod is the static-ip default, as in prowler.")
def cf_sni(item, index):
    certificate = get(_cfg(item), "ViewerCertificate", dict)
    reference = optional(certificate, "Certificate", "", str)
    if not reference:
        return "NOT_APPLICABLE", {"reason": "distribution uses no custom viewer certificate"}
    method = optional(certificate, "SSLSupportMethod", "static-ip", str)
    if method not in ("sni-only", "vip", "static-ip"):
        return unknown("unrecognized SSL support method", ssl_support_method=method)
    return result(method != "sni-only", ssl_support_method=method)


@install("aws.c2b.cloudfront.logging_any", "cloudfront_distribution", "CloudFront distribution has standard, real-time or v2 (CloudWatch Logs delivery) logging",
         _cf(Logging={"Enabled": True, "Bucket": "logs.s3.amazonaws.com", "Prefix": "", "IncludeCookies": False}, DefaultCacheBehavior={"ViewerProtocolPolicy": "https-only"}),
         {**_cf(Logging={"Enabled": False, "Bucket": "", "Prefix": "", "IncludeCookies": False}, DefaultCacheBehavior={"ViewerProtocolPolicy": "https-only"}),
          "LogDeliveries": {"collection_status": "collected", "deliveries": []}},
         rows=[P + "cloudfront_distributions_logging_enabled"], severity="medium", control="AU-2",
         remediation="Enable standard logging (legacy S3 or v2 CloudWatch Logs delivery) or attach a real-time log configuration to the distribution.",
         docs=[D_CF_LOG, D_LOGS],
         extra={"realtime_pass": _cf(DefaultCacheBehavior={"ViewerProtocolPolicy": "https-only", "RealtimeLogConfigArn": "arn:aws:cloudfront::" + ACCOUNT + ":realtime-log-config/rt"}),
                "v2_pass": {**_cf(DefaultCacheBehavior={"ViewerProtocolPolicy": "https-only"}),
                            "LogDeliveries": {"collection_status": "collected", "deliveries": [{"deliverySourceName": "cf-E1", "deliveryDestinationArn": "arn:aws:logs:us-east-1:" + ACCOUNT + ":delivery-destination:d"}]}},
                "no_v2_fact": _cf(DefaultCacheBehavior={"ViewerProtocolPolicy": "https-only"}), "no_v2_fact_expect": "UNKNOWN"},
         note="Legacy Logging.Enabled or a default-behavior RealtimeLogConfigArn passes directly; otherwise the v2 delivery fact (COLLECTOR_FACTS) decides, UNKNOWN until collected.")
def cf_logging(item, index):
    data = _cfg(item)
    legacy = absent_or(data, "CallerReference", "Logging.Enabled", False, bool)
    realtime = optional(get(data, "DefaultCacheBehavior", dict), "RealtimeLogConfigArn", "", str)
    if legacy or realtime:
        return result(False, standard_logging=legacy, realtime_log_config=realtime or None)
    deliveries = detail(item, "LogDeliveries")
    rows = list_of_objects(get(deliveries, "deliveries", list)) if deliveries is not None else []
    return result(not rows, standard_logging=False, realtime_log_config=None, v2_deliveries=len(rows))


@install("aws.c2b.cloudfront.origin_traffic_encrypted", "cloudfront_distribution", "Used CloudFront custom and S3 origins have encrypted origin traffic",
         _cf(DefaultCacheBehavior={"TargetOriginId": "web", "ViewerProtocolPolicy": "redirect-to-https"},
             CacheBehaviors={"Quantity": 0}, Origins=_origins_of(_s3o(), _custom(policy="match-viewer"))),
         _cf(DefaultCacheBehavior={"TargetOriginId": "web", "ViewerProtocolPolicy": "redirect-to-https"},
             CacheBehaviors={"Quantity": 0}, Origins=_origins_of(_s3o(), _custom(policy="http-only"))),
         rows=[P + "cloudfront_distributions_origin_traffic_encrypted"], severity="medium", control="SC-8",
         remediation="For every used custom origin, set OriginProtocolPolicy to https-only, or use match-viewer only when every targeting cache behavior redirects or requires HTTPS. For a used S3 origin, disallow HTTP viewers on every targeting behavior.",
         docs=[D_CF_ORIGIN, D_CF],
         extra={"s3_allow_all": _cf(DefaultCacheBehavior={"TargetOriginId": "s3", "ViewerProtocolPolicy": "allow-all"},
                                    CacheBehaviors={"Quantity": 0}, Origins=_origins_of(_s3o())), "s3_allow_all_expect": "FAIL"},
         note="A proven insecure direct behavior-to-origin route FAILs despite unrelated incomplete evidence. Ambiguous target binding is UNKNOWN. Otherwise incomplete or unsupported used paths, including origin groups, are UNKNOWN; only complete secure paths PASS. The S3 viewer-policy branch retains pinned source parity, including its OAC caveat.")
def cf_origin_traffic(item, index):
    data = _cfg(item)
    origins = _origins(data)
    by_id = {}
    uncertain = []
    origin_binding_unknown = False
    for origin in origins:
        try:
            oid = get(origin, "Id", str)
            if not oid:
                raise Unavailable("empty origin ID")
            by_id.setdefault(oid, []).append(origin)
        except Unavailable as exc:
            origin_binding_unknown = True
            uncertain.append(str(exc))

    # Group IDs share the TargetOriginId namespace. A missing group ID could
    # collide with a direct origin, so no direct binding is proven in that case.
    group_ids = set()
    group_binding_unknown = False
    try:
        groups = optional(data, "OriginGroups", None, dict)
        if groups is not None:
            group_count = get(groups, "Quantity", int)
            if group_count < 0:
                raise Unavailable("invalid origin group quantity")
            group_rows = get(groups, "Items", list) if ("Items" in groups or "Items" in groups.get("_coverage", {})) else []
            if group_count != len(group_rows):
                raise Unavailable("origin group quantity does not match the list")
            for group in group_rows:
                group_id = get(group, "Id", str)
                if not group_id or group_id in group_ids:
                    raise Unavailable("origin group ID missing or duplicated")
                group_ids.add(group_id)
            if group_count:
                uncertain.append("origin groups are not modeled")
    except Unavailable as exc:
        group_binding_unknown = True
        uncertain.append(str(exc))

    behaviors = []
    try:
        behaviors.append(get(data, "DefaultCacheBehavior", dict))
    except Unavailable as exc:
        uncertain.append(str(exc))
    try:
        cache = get(data, "CacheBehaviors", dict)
        try:
            quantity = get(cache, "Quantity", int)
            if quantity < 0:
                raise Unavailable("invalid cache behavior quantity")
        except Unavailable as exc:
            quantity = None
            uncertain.append(str(exc))
        try:
            additional = get(cache, "Items", list) if ("Items" in cache or "Items" in cache.get("_coverage", {})) else []
            if quantity is not None and quantity != len(additional):
                uncertain.append("cache behavior quantity does not match the list")
            for behavior in additional:
                if isinstance(behavior, dict):
                    behaviors.append(behavior)
                else:
                    uncertain.append("malformed cache behavior")
        except Unavailable as exc:
            uncertain.append(str(exc))
    except Unavailable as exc:
        uncertain.append(str(exc))

    plaintext = set()
    for behavior in behaviors:
        try:
            target = get(behavior, "TargetOriginId", str)
            if not target or origin_binding_unknown or group_binding_unknown or target in group_ids or len(by_id.get(target, [])) != 1:
                raise Unavailable("cache behavior target binding is ambiguous, grouped, or unknown")
            origin = by_id[target][0]
            s3 = optional(origin, "S3OriginConfig", None, dict)
            custom = optional(origin, "CustomOriginConfig", None, dict)
            if (s3 is None) == (custom is None) or s3 == {}:
                raise Unavailable("target origin configuration is missing or contradictory")
            if s3 is not None:
                get(s3, "OriginAccessIdentity", str)
                policy = None
            else:
                policy = get(custom, "OriginProtocolPolicy", str)
                if policy not in ("http-only", "https-only", "match-viewer"):
                    raise Unavailable("unrecognized target origin protocol policy")
            if policy == "http-only":
                plaintext.add(target)
                continue
            viewer = get(behavior, "ViewerProtocolPolicy", str)
            if viewer not in VIEWER:
                raise Unavailable("unrecognized viewer protocol policy")
            if (s3 is not None or policy == "match-viewer") and viewer == "allow-all":
                plaintext.add(target)
        except Unavailable as exc:
            uncertain.append(str(exc))
    if plaintext:
        return result(True, unencrypted_origins=sorted(plaintext))
    if uncertain:
        return unknown("incomplete, ambiguous, or unsupported origin traffic evidence", details=sorted(set(uncertain)))
    return result(False, unencrypted_origins=[])


@install("aws.c2b.cloudfront.pqc_tls", "cloudfront_distribution", "CloudFront viewer certificate enforces a post-quantum TLS security policy",
         _cf(ViewerCertificate={"CloudFrontDefaultCertificate": False, "MinimumProtocolVersion": "TLSv1.3_2025"}),
         _cf(ViewerCertificate={"CloudFrontDefaultCertificate": False, "MinimumProtocolVersion": "TLSv1.2_2021"}),
         rows=[P + "cloudfront_distributions_pqc_tls_enabled"], severity="low", control="SC-13",
         remediation="Use a custom certificate and set MinimumProtocolVersion to TLSv1.3_2025.", docs=[D_CF_TLS, D_CF_VC],
         extra={"default_certificate": _cf(ViewerCertificate={"CloudFrontDefaultCertificate": True, "MinimumProtocolVersion": "TLSv1"}), "default_certificate_expect": "FAIL"},
         note="Pinned prowler PQC_CLOUDFRONT_POLICIES_DEFAULT = " + str(CF_PQC) + ".")
def cf_pqc(item, index):
    certificate = get(_cfg(item), "ViewerCertificate", dict)
    default = optional(certificate, "CloudFrontDefaultCertificate", False, bool)
    version = optional(certificate, "MinimumProtocolVersion", "", str)
    return result(default or version not in CF_PQC, cloudfront_default_certificate=default, minimum_protocol_version=version or None, allowed=CF_PQC)


@install("aws.c2b.cloudfront.s3_origin_access_control", "cloudfront_distribution", "CloudFront S3 origins use origin access control (OAC)",
         _cf(Origins=_origins_of(_s3o(oac="E2OAC"), _custom())), _cf(Origins=_origins_of(_s3o(oac="E2OAC"), _s3o("legacy", "old", oai="origin-access-identity/cloudfront/E3"))),
         rows=[P + "cloudfront_distributions_s3_origin_access_control"], severity="medium", control="AC-3",
         remediation="Create an origin access control, set OriginAccessControlId on every S3 origin and restrict the bucket policy to the distribution.",
         docs=[D_CF_OAC, D_CF_ORIGIN], extra={"not_applicable": _cf(Origins=_origins_of(_custom()))})
def cf_oac(item, index):
    origins = [row for row in _origins(_cfg(item)) if _s3_config(row)]
    if not origins:
        return "NOT_APPLICABLE", {"reason": "distribution has no S3 origin"}
    missing = [get(row, "Id", str) for row in origins if not optional(row, "OriginAccessControlId", "", str)]
    return result(bool(missing), s3_origins_without_oac=missing)


def _bucket_name(origin):
    domain = get(origin, "DomainName", str)
    if _s3_config(origin) or ".s3." in domain:
        return domain.split(".s3")[0]
    return None


@install("aws.c2b.cloudfront.s3_origin_bucket_exists", "cloudfront_distribution", "CloudFront S3 origins point to existing buckets",
         _cf(Origins=_origins_of(_s3o(bucket="site"), _custom())),
         {**_cf(Origins=_origins_of(_s3o(bucket="gone"))), "OriginBucketProbes": {"collection_status": "collected", "results": [{"Bucket": "gone", "HttpStatusCode": 404}]}},
         rows=[P + "cloudfront_distributions_s3_origin_non_existent_bucket", C + "cloudfront_distribution_no_non_existent_s3_origin",
               C + "foundational_security_cloudfront_12"], severity="high", control="CM-8", dependencies=["bucket"],
         remediation="Recreate the bucket in an account you own or repoint/remove the origin so the bucket name cannot be claimed by someone else.",
         docs=[D_CF_ORIGIN, D_HEAD],
         extra={"index": inventory("bucket", [{"Name": "site"}]), "not_applicable": _cf(Origins=_origins_of(_custom())),
                "fail_expect": "UNKNOWN", "cross_account_unknown_expect": "UNKNOWN", "cross_account_unknown": {**_cf(Origins=_origins_of(_s3o(bucket="partner"))), "OriginBucketProbes": {"collection_status": "collected", "results": [{"Bucket": "partner", "HttpStatusCode": 403}]}},
                "unprobed": _cf(Origins=_origins_of(_s3o(bucket="partner"))), "unprobed_expect": "UNKNOWN"},
         note="S3 origins are those with S3OriginConfig (prowler) or a '.s3.' domain (steampipe); the bucket is the domain prefix before '.s3'. A bucket in the account inventory exists; otherwise "
              "external origin existence remains UNKNOWN. Bare HeadBucket HTTP error codes cannot distinguish missing buckets from inaccessible buckets, and this collector has no bound origin-probe producer.")
def cf_s3_bucket(item, index):
    names = [name for name in (_bucket_name(row) for row in _origins(_cfg(item))) if name is not None]
    if not names:
        return "NOT_APPLICABLE", {"reason": "distribution has no S3 origin"}
    try:
        owned = {get(row, "Name", str) for row in complete_items(index, "bucket")}
    except Unavailable:
        owned = set()
    # There is no collector-produced, request-bound origin probe contract.
    # HeadBucket 400/403/404 are ambiguous errors, and a synthetic status code
    # (including 200/301) cannot bind a native observation to this origin.
    unresolved = [name for name in names if name not in owned]
    if unresolved:
        return unknown("origin bucket existence not resolvable", buckets=unresolved)
    return result(False, buckets=names)


@install("aws.c2b.cloudfront.origin_no_deprecated_ssl", "cloudfront_distribution", "CloudFront custom origins do not allow SSLv3, TLSv1 or TLSv1.1",
         _cf(Origins=_origins_of(_custom(protocols=("TLSv1.2",)), _s3o())), _cf(Origins=_origins_of(_custom(protocols=("TLSv1.1", "TLSv1.2")))),
         rows=[P + "cloudfront_distributions_using_deprecated_ssl_protocols"], severity="low", control="SC-8",
         remediation="Restrict every custom origin's OriginSslProtocols to TLSv1.2.", docs=[D_CF_ORIGIN])
def cf_origin_ssl(item, index):
    deprecated = []
    for origin in _origins(_cfg(item)):
        items = absent_or(origin, "Id", "CustomOriginConfig.OriginSslProtocols.Items", [], list)
        deprecated += [get(origin, "Id", str) + ":" + p for p in strings(items, "OriginSslProtocols") if p in DEPRECATED_ORIGIN_SSL]
    return result(bool(deprecated), deprecated_origin_protocols=deprecated)


@install("aws.c2b.cloudfront.s3_origin_access_identity", "cloudfront_distribution", "CloudFront s3.amazonaws.com origins declare an origin access identity",
         _cf(Origins=_origins_of(_s3o(oai="origin-access-identity/cloudfront/E3"), _custom())), _cf(Origins=_origins_of(_s3o(oai=""))),
         rows=[C + "cloudfront_distribution_origin_access_identity_enabled"], severity="medium", control="AC-3",
         remediation="Restrict S3 origins to CloudFront (prefer origin access control; an OAI satisfies this control).", docs=[D_CF_S3, D_CF_OAC],
         extra={"not_applicable": _cf(Origins=_origins_of(_custom()))},
         note="Faithful to the pinned query: only DomainName like '%s3.amazonaws.com' is evaluated and an empty OriginAccessIdentity alarms, so OAC-only origins fail here "
              "(AWS documents an empty OriginAccessIdentity with OAC). aws.c2b.cloudfront.s3_origin_access_control is the OAC check.")
def cf_oai(item, index):
    origins = [row for row in _origins(_cfg(item)) if get(row, "DomainName", str).endswith("s3.amazonaws.com")]
    if not origins:
        return "NOT_APPLICABLE", {"reason": "no s3.amazonaws.com origin"}
    missing = []
    for row in origins:
        config = _s3_config(row)
        if config and optional(config, "OriginAccessIdentity", None, str) == "":
            missing.append(get(row, "Id", str))
    return result(bool(missing), origins_without_oai=missing)


@install("aws.c2b.cloudfront.recommended_tls_policy", "cloudfront_distribution", "CloudFront viewer certificate uses the recommended TLS security policy",
         _cf(ViewerCertificate={"CloudFrontDefaultCertificate": False, "MinimumProtocolVersion": "TLSv1.2_2021"}),
         _cf(ViewerCertificate={"CloudFrontDefaultCertificate": True, "MinimumProtocolVersion": "TLSv1"}),
         rows=[C + "cloudfront_distribution_uses_recommended_tls_security_policy", C + "foundational_security_cloudfront_15"], severity="medium", control="SC-8",
         remediation="Use a custom certificate and set MinimumProtocolVersion to TLSv1.2_2021.", docs=[D_CF_TLS, D_CF_VC],
         extra={"no_certificate": _cf(), "no_certificate_expect": "FAIL"},
         note="Pinned variable cloudfront_distribution_tls_security_policy = " + str(CF_RECOMMENDED_TLS) + "; a missing ViewerCertificate alarms.")
def cf_recommended_tls(item, index):
    data = _cfg(item)
    certificate = absent_or(data, "CallerReference", "ViewerCertificate", None, dict)
    if certificate is None:
        return result(True, viewer_certificate=None)
    version = optional(certificate, "MinimumProtocolVersion", None, str)
    return result(version not in CF_RECOMMENDED_TLS, minimum_protocol_version=version, allowed=CF_RECOMMENDED_TLS)


# =========================================================================== ELBv2
LB_ARN = "arn:aws:elasticloadbalancing:us-east-1:" + ACCOUNT + ":loadbalancer/app/web/1"
ACM_ARN = "arn:aws:acm:us-east-1:" + ACCOUNT + ":certificate/c1"
IAM_CERT_ARN = "arn:aws:iam::" + ACCOUNT + ":server-certificate/legacy"
# prowler elbv2_insecure_ssl_ciphers secure_ssl_policies (pinned)
PQ_POLICIES = ["ELBSecurityPolicy-TLS13-1-2-PQ-2025-09", "ELBSecurityPolicy-TLS13-1-2-Ext1-PQ-2025-09", "ELBSecurityPolicy-TLS13-1-2-Ext2-PQ-2025-09",
               "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09", "ELBSecurityPolicy-TLS13-1-3-PQ-2025-09", "ELBSecurityPolicy-TLS13-1-2-FIPS-PQ-2025-09",
               "ELBSecurityPolicy-TLS13-1-2-Ext0-FIPS-PQ-2025-09", "ELBSecurityPolicy-TLS13-1-2-Ext1-FIPS-PQ-2025-09", "ELBSecurityPolicy-TLS13-1-2-Ext2-FIPS-PQ-2025-09",
               "ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09", "ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09"]
SECURE_POLICIES = ["ELBSecurityPolicy-TLS-1-2-2017-01", "ELBSecurityPolicy-TLS-1-2-Ext-2018-06", "ELBSecurityPolicy-FS-1-2-2019-08",
                   "ELBSecurityPolicy-FS-1-2-Res-2019-08", "ELBSecurityPolicy-FS-1-2-Res-2020-10", "ELBSecurityPolicy-TLS13-1-2-2021-06",
                   "ELBSecurityPolicy-TLS13-1-3-2021-06", "ELBSecurityPolicy-TLS13-1-2-Res-2021-06", "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
                   "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06"] + PQ_POLICIES
# Security Hub ELB.17 fixed, noncustomizable sslPolicies parameter, re-reviewed 2026-11-17 against
# https://docs.aws.amazon.com/securityhub/latest/userguide/elb-controls.html#elb-17. AWS dropped the
# 2021-06/2023-04 Res policies and added the RFC9151 FIPS and TLS13-1-2 (FIPS-)PQ policies. The plain
# ELBSecurityPolicy-TLS13-1-2-2021-06 (the ELB default) is not on the list. The pinned Steampipe default
# has different names; that source divergence stays in the check note.
RECOMMENDED_POLICIES = ["ELBSecurityPolicy-TLS13-1-3-2021-06", "ELBSecurityPolicy-TLS13-1-3-FIPS-2023-04",
                        "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09", "ELBSecurityPolicy-TLS13-1-3-PQ-2025-09",
                        "ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09", "ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09",
                        "ELBSecurityPolicy-TLS13-1-2-RFC9151-FIPS-2023-07", "ELBSecurityPolicy-TLS13-1-2-RFC9151-INTEROP1-FIPS-2023-07",
                        "ELBSecurityPolicy-TLS13-1-2-RFC9151-INTEROP2-FIPS-2023-07", "ELBSecurityPolicy-TLS13-1-3-RFC9151-FIPS-2023-07",
                        "ELBSecurityPolicy-TLS13-1-2-FIPS-PQ-2025-09", "ELBSecurityPolicy-TLS13-1-2-PQ-2025-09"]
# Explicitly source-reviewed names only. An unrecognized future name must not
# be reported as a definite obsolete policy solely from its spelling.
REVIEWED_NON_RECOMMENDED_POLICIES = (set(SECURE_POLICIES) | set(PQ_POLICIES) |
    {"ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04", "ELBSecurityPolicy-TLS13-1-2-2021-06",
     "ELBSecurityPolicy-TLS13-1-2-Res-2021-06", "ELBSecurityPolicy-TLS13-1-2-Res-FIPS-2023-04",
     "ELBSecurityPolicy-TLS13-1-0-2021-06", "ELBSecurityPolicy-TLS13-1-1-2021-06",
     "ELBSecurityPolicy-TLS-1-1-2017-01", "ELBSecurityPolicy-2016-08", "ELBSecurityPolicy-2015-05"}) - set(RECOMMENDED_POLICIES)
GOOD_POLICY = "ELBSecurityPolicy-TLS13-1-2-2021-06"
OLD_POLICY = "ELBSecurityPolicy-2016-08"


def _l(protocol, policy=None, certs=(), actions=None, port=443, rules=None):
    row = {"ListenerArn": LB_ARN.replace(":loadbalancer/", ":listener/") + "/" + str(port), "Protocol": protocol, "Port": port,
           "DefaultActions": actions or [{"Type": "forward", "TargetGroupArn": "arn:tg"}]}
    if policy:
        row["SslPolicy"] = policy
    if certs:
        row["Certificates"] = [{"CertificateArn": c} for c in certs]
    if rules is not None:
        row["Rules"] = {"collection_status": "collected" if rules else "empty", "items": list(rules)}
    return row


REDIRECT = [{"Type": "redirect", "RedirectConfig": {"Protocol": "HTTPS", "Port": "443", "StatusCode": "HTTP_301"}}]
REDIRECT_RULE = {"RuleArn": "default", "IsDefault": True, "Actions": REDIRECT}
FORWARD_RULE = {"RuleArn": "default", "IsDefault": True, "Actions": [{"Type": "forward", "TargetGroupArn": "arn:tg"}]}


def _lb(kind="application", listeners=(), attrs=None, scheme="internal", groups=None):
    item = {"LoadBalancerArn": LB_ARN, "LoadBalancerName": "web", "Type": kind, "Scheme": scheme,
            "Listeners": {"collection_status": "collected" if listeners else "empty", "items": list(listeners)}}
    if attrs is not None:
        item["Attributes"] = {"Attributes": [{"Key": k, "Value": v} for k, v in attrs.items()]}
    if groups is not None:
        item["SecurityGroups"] = list(groups)
    return item


def _sg(gid="sg-1", ingress=None, egress=None):
    return {"GroupId": gid, "IpPermissions": [] if ingress is None else ingress, "IpPermissionsEgress": [] if egress is None else egress}


OPEN_ALL = {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}
HTTPS_WORLD = {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}


def _type(item):
    kind = get(item, "Type", str)
    if kind not in ("application", "network", "gateway"):
        raise Unavailable("unrecognized load balancer type")
    return kind


def _listeners(item):
    return detail_list(item, "Listeners")


def _protocol(listener):
    return get(listener, "Protocol", str)


def _policy(listener):
    return optional(listener, "SslPolicy", None, str)


def _certificates(listener):
    return [get(row, "CertificateArn", str) for row in list_of_objects(optional(listener, "Certificates", [], list))]


def _attrs(item):
    out = {}
    for row in list_of_objects(get(item, "Attributes.Attributes", list)):
        key = get(row, "Key", str)
        if key in out:
            raise Unavailable("duplicate load balancer attribute")
        out[key] = get(row, "Value", str)
    return out


def _redirects_https(actions):
    return any(get(a, "Type", str) == "redirect" and optional(get(a, "RedirectConfig", dict), "Protocol", "", str) == "HTTPS" for a in list_of_objects(actions))


@install("aws.c2b.elbv2.cross_zone_enabled", "load_balancer", "Network/gateway load balancer enables cross-zone load balancing",
         _lb("network", attrs={"load_balancing.cross_zone.enabled": "true"}), _lb("network", attrs={"load_balancing.cross_zone.enabled": "false"}),
         rows=[P + "elbv2_cross_zone_load_balancing_enabled"], severity="medium", control="CP-10",
         remediation="Set the load_balancing.cross_zone.enabled attribute to true.", docs=[D_LB_ATTR],
         extra={"not_applicable": _lb("application", attrs={})},
         note="Application load balancers always balance across zones and are not applicable, as in prowler.")
def v2_cross_zone(item, index):
    kind = _type(item)
    if kind == "application":
        return "NOT_APPLICABLE", {"type": kind}
    value = _attrs(item).get("load_balancing.cross_zone.enabled")
    if value not in ("true", "false"):
        return unknown("cross-zone attribute absent or unrecognized")
    return result(value != "true", load_balancer_type=kind, cross_zone=value)


@install("aws.c2b.elbv2.insecure_ssl_ciphers", "load_balancer", "ELBv2 HTTPS listeners use a secure TLS security policy",
         _lb(listeners=[_l("HTTPS", GOOD_POLICY, [ACM_ARN]), _l("HTTP", port=80)]), _lb(listeners=[_l("HTTPS", OLD_POLICY, [ACM_ARN])]),
         rows=[P + "elbv2_insecure_ssl_ciphers"], severity="medium", control="SC-8",
         remediation="Move every HTTPS listener to a TLS 1.2+ policy such as ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09.", docs=[D_ALB_POL],
         note="Pinned prowler secure_ssl_policies (21 policies, including the 2025-09 PQ policies); only HTTPS listeners are evaluated.")
def v2_ciphers(item, index):
    _type(item)
    weak = [_policy(row) for row in _listeners(item) if _protocol(row) == "HTTPS" and _policy(row) not in SECURE_POLICIES]
    return result(bool(weak), insecure_policies=weak)


@install("aws.c2b.elbv2.internet_facing_open_sg", "load_balancer", "Internet-facing ELBv2 security groups do not allow all TCP traffic from anywhere",
         _lb(scheme="internet-facing", groups=["sg-1"]), _lb(scheme="internet-facing", groups=["sg-1"]),
         rows=[P + "elbv2_internet_facing"], severity="medium", category="exposure", control="SC-7", dependencies=["security_group"],
         remediation="Make the load balancer internal or restrict its security groups to the ports and sources it serves.", docs=[D_LB, D_SG],
         extra={"pass_index": inventory("security_group", [_sg(ingress=[HTTPS_WORLD])]), "fail_index": inventory("security_group", [_sg(ingress=[OPEN_ALL])]),
                "internal_pass": _lb(scheme="internal", groups=["sg-1"])},
         note="Prowler semantics: FAIL only for internet-facing load balancers with an attached security group rule open to 0.0.0.0/0 or ::/0 for all protocols or all TCP ports.")
def v2_internet(item, index):
    _type(item)
    scheme = get(item, "Scheme", str)
    if scheme != "internet-facing":
        return result(False, scheme=scheme)
    ids = strings(optional(item, "SecurityGroups", [], list), "SecurityGroups")
    open_groups = [get(g, "GroupId", str) for g in security_groups(index, ids)
                   if any(sg_rule_open(rule, "tcp", None, any_address=True) for rule in list_of_objects(get(g, "IpPermissions", list)))]
    return result(bool(open_groups), scheme=scheme, open_security_groups=open_groups)


def _tls_listeners(item):
    return [row for row in _listeners(item) if _protocol(row) in ("HTTPS", "TLS")]


@install("aws.c2b.elbv2.listener_fips_tls", "load_balancer", "ELBv2 HTTPS/TLS listeners use FIPS security policies",
         _lb(listeners=[_l("HTTPS", "ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04", [ACM_ARN])]), _lb(listeners=[_l("HTTPS", GOOD_POLICY, [ACM_ARN])]),
         rows=[P + "elbv2_listener_fips_tls_enabled"], severity="low", control="SC-13",
         remediation="Use a FIPS security policy (for example ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09) on every HTTPS/TLS listener.", docs=[D_ALB_POL, D_NLB_POL],
         extra={"no_tls_pass": _lb(listeners=[_l("HTTP", port=80)])})
def v2_fips(item, index):
    _type(item)
    plain = [_policy(row) for row in _tls_listeners(item) if "FIPS" not in (_policy(row) or "").split("-")]
    return result(bool(plain), non_fips_policies=plain)


@install("aws.c2b.elbv2.listener_pqc_tls", "load_balancer", "ELBv2 HTTPS/TLS listeners use post-quantum TLS security policies",
         _lb(listeners=[_l("HTTPS", "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09", [ACM_ARN])]), _lb(listeners=[_l("TLS", GOOD_POLICY, [ACM_ARN])]),
         rows=[P + "elbv2_listener_pqc_tls_enabled"], severity="low", control="SC-13",
         remediation="Use a 2025-09 PQ security policy such as ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09 on every HTTPS/TLS listener.", docs=[D_ALB_POL],
         extra={"no_tls_pass": _lb(listeners=[_l("HTTP", port=80)])}, note="Pinned prowler PQ_TLS_POLICIES_DEFAULT (11 policies).")
def v2_pqc(item, index):
    _type(item)
    plain = [_policy(row) for row in _tls_listeners(item) if _policy(row) not in PQ_POLICIES]
    return result(bool(plain), non_pq_policies=plain)


@install("aws.c2b.elbv2.has_listeners", "load_balancer", "ELBv2 load balancer has at least one listener",
         _lb("gateway", listeners=[_l("GENEVE", port=6081)]), _lb("gateway"),
         rows=[P + "elbv2_listeners_underneath"], severity="medium", control="CM-8",
         remediation="Add a listener or delete the unused load balancer.", docs=[D_LISTENER],
         note="All ELBv2 types including gateway (aws.b.elbv2.listener_presence excludes gateway).")
def v2_has_listeners(item, index):
    kind = _type(item)
    rows = _listeners(item)
    return result(not rows, load_balancer_type=kind, listener_count=len(rows))


@install("aws.c2b.elbv2.nlb_tls_termination", "load_balancer", "Network load balancer terminates TLS on at least one listener",
         _lb("network", listeners=[_l("TLS", GOOD_POLICY, [ACM_ARN])]), _lb("network", listeners=[_l("TCP", port=443)]),
         rows=[P + "elbv2_nlb_tls_termination_enabled"], severity="medium", control="SC-8",
         remediation="Add a TLS listener with an ACM certificate to the network load balancer.", docs=[D_LISTENER, D_NLB_POL],
         extra={"not_applicable": _lb("application")})
def v2_nlb_tls(item, index):
    kind = _type(item)
    if kind != "network":
        return "NOT_APPLICABLE", {"type": kind}
    protocols = [_protocol(row) for row in _listeners(item)]
    return result("TLS" not in protocols, protocols=protocols)


def _routing_redirects_https(actions):
    """True/False for the terminal routing action of an ALB action list; None when missing or malformed."""
    actions = list_of_objects(actions)
    routing = []
    for action in actions:
        action_type = get(action, "Type", str)
        if action_type in ("forward", "redirect", "fixed-response"):
            routing.append(action)
        elif action_type not in ("authenticate-oidc", "authenticate-cognito", "jwt-validation"):
            return None
    if len(routing) != 1 or routing[0] is not actions[-1]:
        return None
    action = routing[0]
    if get(action, "Type", str) != "redirect":
        return False
    config = get(action, "RedirectConfig", dict)
    # AWS retains the request protocol for #{protocol} or an omitted field.
    protocol = optional(config, "Protocol", "#{protocol}", str)
    return protocol == "HTTPS" if protocol in ("HTTP", "HTTPS", "#{protocol}") else None


def http_redirect_only_status(row):
    """Classify a plaintext ALB listener as "redirect", "serving" or "unresolved".

    Plaintext listeners are serving unless the DescribeListeners default action redirects to HTTPS;
    only then are the DescribeRules facts needed, and incomplete ones are unresolved (UNKNOWN).
    """
    try:
        if _routing_redirects_https(optional(row, "DefaultActions", [], list)) is not True:
            return "serving"
    except Unavailable:
        return "serving"
    try:
        return "redirect" if http_listener_redirects_https(row) else "serving"
    except Unavailable:
        return "unresolved"


def http_listener_redirects_https(row):
    """Whether an ALB HTTP listener only redirects to HTTPS (Security Hub ELB.1 semantics).

    True when the default action and every DescribeRules routing action redirect to HTTPS, so the
    listener never serves content in plaintext. False when a known action forwards or responds.
    Raises Unavailable when the default action or rules are missing, malformed or inconsistent.
    """
    default_redirect = _routing_redirects_https(get(row, "DefaultActions", list))
    rules_container = get(row, "Rules", dict)
    get(rules_container, "items", list)
    rules = detail_list(row, "Rules")
    default_rules = [rule for rule in rules if get(rule, "IsDefault", bool)]
    if len(default_rules) != 1:
        raise Unavailable("default listener rule missing or duplicated")
    rule_redirects = [_routing_redirects_https(get(rule, "Actions", list)) for rule in rules]
    default_rule_redirect = rule_redirects[rules.index(default_rules[0])]
    if default_redirect is None or any(value is None for value in rule_redirects) or default_redirect != default_rule_redirect:
        raise Unavailable("listener rule actions incomplete or inconsistent with default action")
    return bool(default_redirect) and all(rule_redirects)


@install("aws.c2b.elbv2.http_listeners_redirect_https", "load_balancer", "ALB HTTP listener defaults and all rules redirect to HTTPS",
         _lb(listeners=[_l("HTTPS", GOOD_POLICY, [ACM_ARN]), _l("HTTP", port=80, actions=REDIRECT,
                            rules=[{"RuleArn": "default", "IsDefault": True, "Actions": REDIRECT}])]),
         _lb(listeners=[_l("HTTP", port=80, rules=[{"RuleArn": "r", "IsDefault": True, "Actions": [{"Type": "forward"}]}])]),
         rows=[P + "elbv2_ssl_listeners"], severity="medium", control="SC-8",
         remediation="Set every HTTP listener default action and every conditional routing action to redirect to HTTPS.", docs=[D_LISTENER, D_RULES, D_REDIRECT],
         extra={"not_applicable": _lb("network"),
                "conditional_redirect_default_forward": _lb(listeners=[_l("HTTP", port=80, rules=[
                    {"RuleArn": "conditional", "IsDefault": False, "Actions": REDIRECT},
                    {"RuleArn": "default", "IsDefault": True, "Actions": [{"Type": "forward"}]}])]),
                "conditional_redirect_default_forward_expect": "FAIL",
                "no_rules": _lb(listeners=[_l("HTTP", port=80)]), "no_rules_expect": "UNKNOWN"},
         note="DescribeRules must be complete for every HTTP listener (COLLECTOR_FACTS). AWS evaluates conditional rules before the default rule, "
              "so both the default action and every conditional routing action must redirect to HTTPS; partial or conflicting facts are UNKNOWN. "
              "This also corrects the source's any-listener PASS behavior.")
def v2_http_redirect(item, index):
    kind = _type(item)
    if kind != "application":
        return "NOT_APPLICABLE", {"type": kind}
    listeners = get(item, "Listeners", dict)
    get(listeners, "items", list)  # A collected container without items is incomplete.
    plain, unresolved = [], []
    for row in _listeners(item):
        try:
            arn = get(row, "ListenerArn", str)
            protocol = _protocol(row)
        except Unavailable:
            unresolved.append("listener with incomplete identity or protocol")
            continue
        if protocol not in ("HTTP", "HTTPS"):
            unresolved.append(arn)
            continue
        if protocol != "HTTP":
            continue
        try:
            if not http_listener_redirects_https(row):
                plain.append(arn)
        except Unavailable:
            unresolved.append(arn)
    if plain:
        return result(True, http_listeners_without_redirect=plain)
    if unresolved:
        return unknown("listener rules or actions incomplete", listeners=unresolved)
    return result(False, http_listeners_without_redirect=[])


def _acl_arns(index, kind):
    arns = set()
    for acl in complete_items(index, kind):
        found = detail(acl, "ResourceArns")
        arns.update(strings(get(found if found is not None else {"ResourceArns": []}, "ResourceArns", list), "ResourceArns"))
    return arns


def _waf_kinds(item, index, kinds):
    kind = _type(item)
    if kind != "application":
        return "NOT_APPLICABLE", {"type": kind}
    arn = get(item, "LoadBalancerArn", str)
    attached, gaps = [], []
    for waf in kinds:
        try:
            if arn in _acl_arns(index, waf):
                attached.append(waf)
        except Unavailable:
            gaps.append(waf)
    if attached:
        return result(False, web_acl_families=attached)
    if gaps:
        return unknown("web ACL associations not collected", families=gaps)
    return result(True, web_acl_families=[])


_V2_ACL = {"ARN": "arn:aws:wafv2:us-east-1:" + ACCOUNT + ":regional/webacl/a/1", "Name": "a", "Id": "1"}
_WAFR_ACL = {"WebACLId": "w1", "Name": "w"}


def _assoc(acl, arns):
    return {**acl, "ResourceArns": {"collection_status": "collected", "ResourceArns": list(arns)}}


@install("aws.c2b.elbv2.alb_waf_attached", "load_balancer", "ALB is associated with a WAFv2 or WAF Classic regional web ACL",
         _lb(), _lb(), rows=[P + "elbv2_waf_acl_attached", C + "elb_application_lb_waf_enabled"], severity="medium", category="exposure", control="SC-7",
         dependencies=["wafv2_web_acl", "wafregional_web_acl"],
         remediation="Associate an AWS WAF web ACL with the application load balancer.", docs=[D_WAFV2, D_WAFR],
         extra={"pass_index": indexes(inventory("wafv2_web_acl", [_assoc(_V2_ACL, [LB_ARN])]), inventory("wafregional_web_acl", [])),
                "fail_index": indexes(inventory("wafv2_web_acl", [_assoc(_V2_ACL, [])]), inventory("wafregional_web_acl", [{**_WAFR_ACL, "ResourceArns": ABSENT}])),
                "classic_pass": _lb(), "classic_pass_index": indexes(inventory("wafv2_web_acl", []), inventory("wafregional_web_acl", [_assoc(_WAFR_ACL, [LB_ARN])])),
                "not_applicable": _lb("network")})
def v2_waf(item, index):
    return _waf_kinds(item, index, ("wafv2_web_acl", "wafregional_web_acl"))


@install("aws.c2b.elbv2.alb_wafv2_attached", "load_balancer", "ALB is associated with a WAFv2 web ACL",
         _lb(), _lb(), rows=[X + "elb_application_lb_waf_enabled"], severity="medium", category="exposure", control="SC-7", dependencies=["wafv2_web_acl"],
         remediation="Associate an AWS WAFv2 web ACL with the application load balancer.", docs=[D_WAFV2],
         extra={"pass_index": inventory("wafv2_web_acl", [_assoc(_V2_ACL, [LB_ARN])]), "fail_index": inventory("wafv2_web_acl", [_assoc(_V2_ACL, ["arn:other"])]),
                "not_applicable": _lb("network")},
         note="aws-perimeter joins aws_wafv2_web_acl associated_resources only; WAF Classic associations do not count.")
def v2_wafv2(item, index):
    return _waf_kinds(item, index, ("wafv2_web_acl",))


@install("aws.c2b.elbv2.not_internet_facing", "load_balancer", "Application/network load balancer is not internet-facing",
         _lb("network"), _lb("application", scheme="internet-facing"),
         rows=[C + "elb_application_classic_network_lb_prohibit_public_access"], severity="medium", category="exposure", control="SC-7",
         remediation="Use an internal scheme unless the load balancer must serve the internet; front public ones with WAF and restrictive security groups.",
         docs=[D_LB], extra={"not_applicable": _lb("gateway")}, note="ELBv2 half of the pinned union (application + network); gateway load balancers are outside it.")
def v2_public(item, index):
    kind = _type(item)
    if kind == "gateway":
        return "NOT_APPLICABLE", {"type": kind}
    scheme = get(item, "Scheme", str)
    return result(scheme == "internet-facing", scheme=scheme, load_balancer_type=kind)


def _cert_days(index, arn, now):
    if ":acm:" in arn:
        for row in complete_items(index, "acm_certificate"):
            if get(row, "CertificateArn", str) == arn:
                return days_between(parse_time(get(row, "Certificate.Certificate.NotAfter", str)), now)
    elif ":iam:" in arn:
        for row in complete_items(index, "iam_server_certificate"):
            if get(row, "Arn", str) == arn:
                return days_between(parse_time(get(row, "Expiration", str)), now)
    raise Unavailable("listener certificate not resolvable")


def _acm(arn, not_after, kind="AMAZON_ISSUED"):
    return {"CertificateArn": arn, "Certificate": {"Certificate": {"CertificateArn": arn, "NotAfter": not_after, "Type": kind}}}


for _days, _sev in ((30, "medium"), (7, "medium")):
    def _expiry(days, severity):
        @install("aws.c2b.elbv2.listener_certificate_" + str(days) + "_days", "load_balancer",
                 "ELB listener certificates are valid for at least " + str(days) + " more days",
                 _lb(listeners=[_l("HTTPS", GOOD_POLICY, [ACM_ARN])]), _lb(listeners=[_l("HTTPS", GOOD_POLICY, [ACM_ARN])]),
                 rows=[C + "elb_application_lb_listener_certificate_expire_" + str(days) + "_days"], severity=severity, control="SC-17",
                 dependencies=["acm_certificate", "iam_server_certificate"],
                 remediation="Renew or replace the listener certificate (prefer ACM-issued certificates with managed renewal).", docs=[D_LISTENER, D_ACM, D_IAM_CERT],
                 extra={"pass_index": indexes(inventory("acm_certificate", [_acm(ACM_ARN, "2026-03-01T00:00:00+00:00")]), inventory("iam_server_certificate", [])),
                        "fail_index": indexes(inventory("acm_certificate", [_acm(ACM_ARN, "2026-01-0" + str(9 if days == 30 else 4) + "T00:00:00+00:00")]),
                                              inventory("iam_server_certificate", [])),
                        "iam": _lb(listeners=[_l("HTTPS", GOOD_POLICY, [IAM_CERT_ARN])]), "iam_expect": "FAIL",
                        "iam_index": indexes(inventory("acm_certificate", []), inventory("iam_server_certificate", [{"Arn": IAM_CERT_ARN, "Expiration": "2025-12-01T00:00:00Z"}])),
                        "not_applicable": _lb(listeners=[_l("HTTP", port=80)])},
                 note="Calendar days between certificate NotAfter and the snapshot clock, alarm below " + str(days) + " (steampipe date(not_after) - current_date). "
                      "Corrected: IAM server certificates are resolved by Expiration instead of alarming on the failed ACM join; unresolvable certificates are UNKNOWN.")
        def evaluate(item, index):
            _type(item)
            arns = [arn for row in _listeners(item) for arn in _certificates(row)]
            if not arns:
                return "NOT_APPLICABLE", {"reason": "no listener certificates"}
            now = parse_time((index.get("context") or {}).get("created_at") if isinstance(index, dict) else None)
            remaining, unresolved = {}, []
            for arn in arns:
                try:
                    remaining[arn] = _cert_days(index, arn, now)
                except Unavailable:
                    unresolved.append(arn)
            expiring = {arn: d for arn, d in remaining.items() if d < days}
            if expiring:
                return result(True, expiring=expiring, minimum_days=days)
            if unresolved:
                return unknown("listener certificate expiry not resolvable", certificates=unresolved)
            return result(False, remaining_days=remaining, minimum_days=days)
        return evaluate
    _expiry(_days, _sev)


@install("aws.c2b.elbv2.alb_http_redirect_default", "load_balancer", "ALB HTTP listeners redirect to HTTPS in their default action",
         _lb(listeners=[_l("HTTPS", GOOD_POLICY, [ACM_ARN]), _l("HTTP", port=80, actions=REDIRECT)]), _lb(listeners=[_l("HTTP", port=80)]),
         rows=[C + "elb_application_lb_redirect_http_request_to_https", C + "foundational_security_elb_1"], severity="medium", control="SC-8",
         remediation="Set the default action of every ALB HTTP listener to a redirect to HTTPS.", docs=[D_LISTENER, "https://docs.aws.amazon.com/securityhub/latest/userguide/elb-controls.html#elb-1"],
         extra={"https_only_pass": _lb(listeners=[_l("HTTPS", GOOD_POLICY, [ACM_ARN])]), "not_applicable": _lb("network")},
         note="Corrected per the AWS Config rule alb-http-to-https-redirection-check behind Security Hub ELB.1: FAIL only when an HTTP listener lacks a default "
              "redirect to HTTPS; HTTPS-only load balancers pass (the pinned query alarms on them).")
def v2_default_redirect(item, index):
    kind = _type(item)
    if kind != "application":
        return "NOT_APPLICABLE", {"type": kind}
    plain = [get(row, "ListenerArn", str) for row in _listeners(item) if _protocol(row) == "HTTP" and not _redirects_https(get(row, "DefaultActions", list))]
    return result(bool(plain), http_listeners_without_redirect=plain)


def _sg_rule_gap(item, index, field):
    ids = strings(optional(item, "SecurityGroups", [], list), "SecurityGroups")
    if not ids:
        return result(True, security_groups=[])
    empty_groups = [get(g, "GroupId", str) for g in security_groups(index, ids) if not list_of_objects(get(g, field, list))]
    return result(bool(empty_groups), security_groups_without_rules=empty_groups, direction=field)


@install("aws.c2b.elbv2.alb_sg_outbound_rule", "load_balancer", "ALB security groups all have outbound rules",
         _lb(groups=["sg-1"]), _lb(groups=["sg-1"]), rows=[C + "elb_application_lb_with_outbound_rule"], severity="medium", category="network", control="SC-7",
         dependencies=["security_group"], remediation="Attach a security group with outbound rules to the targets/health-check ports.", docs=[D_LB, D_SG],
         extra={"pass_index": inventory("security_group", [_sg(egress=[HTTPS_WORLD])]), "fail_index": inventory("security_group", [_sg(egress=[])]),
                "no_groups": _lb(groups=[]), "no_groups_expect": "FAIL", "not_applicable": _lb("network")})
def alb_egress(item, index):
    kind = _type(item)
    if kind != "application":
        return "NOT_APPLICABLE", {"type": kind}
    return _sg_rule_gap(item, index, "IpPermissionsEgress")


@install("aws.c2b.elbv2.recommended_tls_policy", "load_balancer", "ALB HTTPS and NLB TLS listeners use a Security Hub ELB.17 approved policy",
         _lb(listeners=[_l("HTTPS", RECOMMENDED_POLICIES[0], [ACM_ARN]), _l("HTTP", port=80, actions=REDIRECT)]), _lb("network", listeners=[_l("TLS", OLD_POLICY, [ACM_ARN])]),
         rows=[C + "elb_application_network_lb_https_tls_listener_recommended_security_policy", C + "foundational_security_elb_17"], severity="medium", control="SC-8",
         remediation="Review client compatibility and set listener SslPolicy to a current Security Hub ELB.17 approved policy; AWS recommends the 2025-09 Res-PQ or Res-FIPS-PQ policy where supported.", docs=[D_ALB_POL, D_NLB_POL, "https://docs.aws.amazon.com/securityhub/latest/userguide/elb-controls.html#elb-17"],
         extra={"not_applicable": _lb(listeners=[_l("HTTP", port=80)]), "gateway": _lb("gateway"), "gateway_expect": "NOT_APPLICABLE"},
         note="Security Hub ELB.17 fixed sslPolicies parameter reviewed 2026-11-17 = " + str(RECOMMENDED_POLICIES) + ". The pinned Steampipe default set differs "
              "(six older names, no PQ), so its framework row needs separate scope review. Only ALB HTTPS and NLB TLS listeners are evaluated; "
              "known other policies fail, while missing or unreviewed names are UNKNOWN. The pinned query's else branch alarmed on every HTTP/TCP listener.")
def v2_recommended(item, index):
    kind = _type(item)
    if kind == "gateway":
        return "NOT_APPLICABLE", {"type": kind}
    wanted = "HTTPS" if kind == "application" else "TLS"
    rows = [row for row in _listeners(item) if _protocol(row) == wanted]
    if not rows:
        return "NOT_APPLICABLE", {"reason": "no " + wanted + " listener"}
    weak, unresolved = [], []
    for row in rows:
        policy = _policy(row)
        if policy in RECOMMENDED_POLICIES:
            continue
        if policy in REVIEWED_NON_RECOMMENDED_POLICIES:
            weak.append(policy)
        else:
            unresolved.append({"listener_arn": get(row, "ListenerArn", str), "ssl_policy": policy})
    if weak:
        return result(True, non_recommended_policies=weak, unresolved_listeners=unresolved)
    if unresolved:
        return unknown("listener SSL policy is missing or outside reviewed policy table", unresolved_listeners=unresolved)
    return result(False, approved_policies=[_policy(row) for row in rows])


def _plaintext_listeners(item, kind):
    """Split non-TLS listeners into (serving, unresolved, redirect-only) listener rows.

    An ALB HTTP listener whose default action and every rule redirect to HTTPS never serves
    content in plaintext (Security Hub ELB.1 semantics), so it is not a plaintext listener.
    """
    wanted = "HTTPS" if kind == "application" else "TLS"
    serving, unresolved, redirects = [], [], []
    for row in _listeners(item):
        if _protocol(row) == wanted:
            continue
        if kind == "application" and _protocol(row) == "HTTP":
            {"redirect": redirects, "serving": serving, "unresolved": unresolved}[http_redirect_only_status(row)].append(row)
            continue
        serving.append(row)
    return serving, unresolved, redirects


def _listener_label(row):
    return _protocol(row) + ":" + str(get(row, "Port", int))


@install("aws.c2b.elbv2.listeners_acm_certificate", "load_balancer", "Every ALB/NLB listener uses an ACM certificate",
         _lb(listeners=[_l("HTTPS", GOOD_POLICY, [ACM_ARN]), _l("HTTP", port=80, actions=REDIRECT, rules=[REDIRECT_RULE])]),
         _lb(listeners=[_l("HTTPS", GOOD_POLICY, [ACM_ARN]), _l("HTTP", port=80, rules=[FORWARD_RULE])]),
         rows=[C + "elb_application_network_lb_use_ssl_certificate"], severity="medium", control="SC-17",
         remediation="Terminate TLS on every listener with an ACM certificate (replace HTTP/TCP listeners with HTTPS/TLS).", docs=[D_LISTENER, D_ACM, D_RULES],
         extra={"iam": _lb("network", listeners=[_l("TLS", GOOD_POLICY, [IAM_CERT_ARN])]), "iam_expect": "FAIL", "not_applicable": _lb("gateway"),
                "redirect_without_rules": _lb(listeners=[_l("HTTPS", GOOD_POLICY, [ACM_ARN]), _l("HTTP", port=80, actions=REDIRECT)]),
                "redirect_without_rules_expect": "UNKNOWN"},
         note="Pinned query semantics: any listener without an ACM certificate, including plain HTTP/TCP listeners, alarms; no listeners passes. "
              "An ALB HTTP listener whose default action and every rule redirect to HTTPS cannot hold a certificate and serves nothing in "
              "plaintext, so it is excluded; incomplete rule facts for it are UNKNOWN.")
def v2_acm(item, index):
    kind = _type(item)
    if kind == "gateway":
        return "NOT_APPLICABLE", {"type": kind}
    _, unresolved, redirects = _plaintext_listeners(item, kind)
    skipped = {id(row) for row in unresolved + redirects}
    bare = [get(row, "ListenerArn", str) for row in _listeners(item)
            if id(row) not in skipped and not any(":acm:" in arn for arn in _certificates(row))]
    if bare:
        return result(True, listeners_without_acm_certificate=bare)
    if unresolved:
        return unknown("HTTP listener rules incomplete", unresolved_listeners=[get(row, "ListenerArn", str) for row in unresolved])
    return result(False, listeners_without_acm_certificate=[], https_redirect_listeners=[_listener_label(row) for row in redirects])


@install("aws.c2b.elbv2.listeners_secure_protocol", "load_balancer", "ALB listeners use HTTPS and NLB listeners use TLS",
         _lb(listeners=[_l("HTTPS", GOOD_POLICY, [ACM_ARN]), _l("HTTP", port=80, actions=REDIRECT, rules=[REDIRECT_RULE])]),
         _lb(listeners=[_l("HTTPS", GOOD_POLICY, [ACM_ARN]), _l("HTTP", port=80, rules=[FORWARD_RULE])]),
         rows=[C + "elb_application_network_listener_uses_secure_protocol", C + "foundational_security_elb_18"], severity="medium", control="SC-8",
         remediation="Use HTTPS listeners on application load balancers and TLS listeners on network load balancers.", docs=[D_LISTENER, D_RULES, "https://docs.aws.amazon.com/securityhub/latest/userguide/elb-controls.html#elb-18"],
         extra={"not_applicable": _lb("gateway"), "no_listeners": _lb("application"), "no_listeners_expect": "NOT_APPLICABLE",
                "nlb_tls": _lb("network", listeners=[_l("TLS", GOOD_POLICY, [ACM_ARN])]), "nlb_tls_expect": "PASS",
                "nlb_tcp": _lb("network", listeners=[_l("TLS", GOOD_POLICY, [ACM_ARN]), _l("TCP", port=80)]), "nlb_tcp_expect": "FAIL",
                "redirect_without_rules": _lb(listeners=[_l("HTTP", port=80, actions=REDIRECT)]), "redirect_without_rules_expect": "UNKNOWN"},
         note="An ALB HTTP listener whose default action and every rule redirect to HTTPS (Security Hub ELB.1 semantics) serves no plaintext "
              "content and is not flagged; the strict ELB.18 Config rule also flags such redirect listeners. Incomplete rule facts are UNKNOWN.")
def v2_secure_protocol(item, index):
    kind = _type(item)
    if kind == "gateway":
        return "NOT_APPLICABLE", {"type": kind}
    if not _listeners(item):
        return "NOT_APPLICABLE", {"reason": "no listeners"}
    wanted = "HTTPS" if kind == "application" else "TLS"
    serving, unresolved, redirects = _plaintext_listeners(item, kind)
    if serving:
        return result(True, insecure_listeners=[_listener_label(row) for row in serving], required_protocol=wanted)
    if unresolved:
        return unknown("HTTP listener rules incomplete", unresolved_listeners=[_listener_label(row) for row in unresolved])
    return result(False, insecure_listeners=[], required_protocol=wanted, https_redirect_listeners=[_listener_label(row) for row in redirects])


# =========================================================================== Classic ELB
def _cl(protocol, cert=None, policies=(), port=443):
    listener = {"Protocol": protocol, "LoadBalancerPort": port, "InstanceProtocol": "HTTP", "InstancePort": 80}
    if cert:
        listener["SSLCertificateId"] = cert
    return {"Listener": listener, "PolicyNames": list(policies)}


def _clb(listeners=(), scheme="internal", instances=("i-1",), groups=("sg-1",)):
    return {"LoadBalancerName": "classic", "DNSName": "classic.elb.amazonaws.com", "Scheme": scheme, "ListenerDescriptions": list(listeners),
            "Instances": [{"InstanceId": i} for i in instances], "SecurityGroups": list(groups)}


def _clb_listeners(item):
    get(item, "LoadBalancerName", str)
    return [get(row, "Listener", dict) for row in list_of_objects(get(item, "ListenerDescriptions", list))], list_of_objects(get(item, "ListenerDescriptions", list))


@install("aws.c2b.classic_elb.ssl_listeners_only", "classic_load_balancer", "Classic ELB listeners use HTTPS or SSL only",
         _clb([_cl("HTTPS", ACM_ARN)]), _clb([_cl("HTTPS", ACM_ARN), _cl("HTTP", port=80)]),
         rows=[P + "elb_ssl_listeners"], severity="medium", control="SC-8", remediation="Replace HTTP/TCP listeners with HTTPS/SSL listeners.", docs=[D_CLB],
         extra={"none_pass": _clb([])},
         note="Prowler: a load balancer without listeners passes (aws.b.classic_elb.encrypted_listeners reports it NOT_APPLICABLE).")
def clb_ssl(item, index):
    listeners, _ = _clb_listeners(item)
    plain = [get(row, "Protocol", str) for row in listeners if get(row, "Protocol", str) not in ("HTTPS", "SSL")]
    return result(bool(plain), insecure_protocols=plain)


@install("aws.c2b.classic_elb.insecure_ssl_ciphers", "classic_load_balancer", "Classic ELB HTTPS listeners use ELBSecurityPolicy-TLS-1-2-2017-01",
         _clb([_cl("HTTPS", ACM_ARN, ["ELBSecurityPolicy-TLS-1-2-2017-01"])]), _clb([_cl("HTTPS", ACM_ARN, ["ELBSecurityPolicy-2016-08"])]),
         rows=[P + "elb_insecure_ssl_ciphers"], severity="medium", control="SC-8",
         remediation="Attach the predefined ELBSecurityPolicy-TLS-1-2-2017-01 policy to every HTTPS listener.", docs=[D_CLB_POL, D_CLB])
def clb_ciphers(item, index):
    _, rows = _clb_listeners(item)
    weak = [get(row, "Listener.LoadBalancerPort", int) for row in rows if get(row, "Listener.Protocol", str) == "HTTPS"
            and "ELBSecurityPolicy-TLS-1-2-2017-01" not in strings(optional(row, "PolicyNames", [], list), "PolicyNames")]
    return result(bool(weak), listener_ports=weak)


@install("aws.c2b.classic_elb.not_internet_facing", "classic_load_balancer", "Classic ELB is not internet-facing",
         _clb(), _clb(scheme="internet-facing"), rows=[P + "elb_internet_facing", C + "elb_application_classic_network_lb_prohibit_public_access"],
         severity="medium", category="exposure", control="SC-7", remediation="Use an internal Classic ELB or migrate to an internal ALB/NLB.", docs=[D_CLB])
def clb_public(item, index):
    get(item, "LoadBalancerName", str)
    scheme = get(item, "Scheme", str)
    return result(scheme == "internet-facing", scheme=scheme)


@install("aws.c2b.classic_elb.acm_certificates", "classic_load_balancer", "Classic ELB HTTPS/SSL listeners use Amazon-issued ACM certificates",
         _clb([_cl("HTTPS", ACM_ARN)]), _clb([_cl("SSL", IAM_CERT_ARN)]), rows=[P + "elb_ssl_listeners_use_acm_certificate"], severity="medium", control="SC-17",
         dependencies=["acm_certificate"], remediation="Issue the certificate through ACM and attach it to the HTTPS/SSL listeners.", docs=[D_CLB, D_ACM],
         extra={"pass_index": inventory("acm_certificate", [_acm(ACM_ARN, "2027-01-01T00:00:00Z")]), "fail_index": inventory("acm_certificate", []),
                "imported": _clb([_cl("HTTPS", ACM_ARN)]), "imported_expect": "FAIL", "imported_index": inventory("acm_certificate", [_acm(ACM_ARN, "2027-01-01T00:00:00Z", "IMPORTED")])},
         note="Prowler: a certificate absent from the ACM inventory (for example an IAM server certificate) or with Type other than AMAZON_ISSUED fails.")
def clb_acm(item, index):
    listeners, _ = _clb_listeners(item)
    arns = [optional(row, "SSLCertificateId", "", str) for row in listeners if get(row, "Protocol", str) in ("HTTPS", "SSL")]
    arns = [arn for arn in arns if arn]
    if not arns:
        return result(False, certificates=[])
    types = {get(row, "CertificateArn", str): get(row, "Certificate.Certificate.Type", str) for row in complete_items(index, "acm_certificate")}
    bad = [arn for arn in arns if types.get(arn) != "AMAZON_ISSUED"]
    return result(bool(bad), non_acm_issued=bad)


@install("aws.c2b.classic_elb.has_registered_instances", "classic_load_balancer", "Classic ELB has registered instances",
         _clb(), _clb(instances=()), rows=[C + "elb_classic_lb_no_registered_instance"], severity="low", control="CM-8",
         remediation="Register instances or delete the unused Classic ELB.", docs=[D_CLB])
def clb_instances(item, index):
    get(item, "LoadBalancerName", str)
    instances = list_of_objects(get(item, "Instances", list))
    return result(not instances, registered_instances=len(instances))


for _field, _suffix, _row, _title in (("IpPermissions", "sg_inbound_rule", "elb_classic_lb_with_inbound_rule", "inbound"),
                                      ("IpPermissionsEgress", "sg_outbound_rule", "elb_classic_lb_with_outbound_rule", "outbound")):
    def _classic_sg(field, suffix, row, title):
        good = _sg(ingress=[HTTPS_WORLD], egress=[HTTPS_WORLD])
        bad = _sg(ingress=[] if field == "IpPermissions" else [HTTPS_WORLD], egress=[] if field == "IpPermissionsEgress" else [HTTPS_WORLD])

        @install("aws.c2b.classic_elb." + suffix, "classic_load_balancer", "Classic ELB security groups all have " + title + " rules",
                 _clb(), _clb(), rows=[C + row], severity="medium", category="network", control="SC-7", dependencies=["security_group"],
                 remediation="Attach security groups with the " + title + " rules the listeners and health checks need.", docs=[D_CLB, D_SG],
                 extra={"pass_index": inventory("security_group", [good]), "fail_index": inventory("security_group", [bad]),
                        "no_groups": _clb(groups=()), "no_groups_expect": "FAIL"})
        def evaluate(item, index):
            get(item, "LoadBalancerName", str)
            return _sg_rule_gap(item, index, field)
        return evaluate
    _classic_sg(_field, _suffix, _row, _title)


# =========================================================================== API Gateway (REST)
# prowler PQC_APIGATEWAY_POLICIES_DEFAULT
APIGW_PQC = ["SecurityPolicy_TLS13_1_2_FIPS_PFS_PQ_2025_09", "SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09", "SecurityPolicy_TLS13_1_2_PQ_2025_09"]


def _stage(settings=None):
    row = {"stageName": "prod", "deploymentId": "d1"}
    if settings is not None:
        row["methodSettings"] = settings
    return row


def _settings(item):
    get(item, "stageName", str)
    values = optional(item, "methodSettings", {}, dict)
    if any(not isinstance(v, dict) for v in values.values()):
        raise Unavailable("malformed method settings")
    return values


def _rest(types=("REGIONAL",), authorizers=None, resources=None, **extra):
    item = {"id": "a1", "name": "api", "endpointConfiguration": {"types": list(types)}, **extra}
    if authorizers is not None:
        item["Authorizers"] = {"collection_status": "collected" if authorizers else "empty", "items": list(authorizers)}
    if resources is not None:
        item["Resources"] = {"collection_status": "collected" if resources else "empty", "items": list(resources)}
    return item


def _resource(path="/", **methods):
    return {"id": "r" + str(len(path)), "path": path, "resourceMethods": {verb: {"httpMethod": verb, **conf} for verb, conf in methods.items()}}


LAMBDA_AUTH = {"id": "au1", "name": "lambda", "type": "TOKEN", "authorizerUri": "arn:aws:apigateway:us-east-1:lambda:path/fn"}


def _types(item):
    get(item, "id", str)
    types = strings(get(item, "endpointConfiguration.types", list), "endpointConfiguration.types")
    if any(t not in ("EDGE", "REGIONAL", "PRIVATE") for t in types):
        raise Unavailable("unrecognized endpoint type")
    return types


def _methods(item):
    out = []
    for resource in detail_list(item, "Resources"):
        path = get(resource, "path", str)
        for verb, method in optional(resource, "resourceMethods", {}, dict).items():
            if not isinstance(method, dict):
                raise Unavailable("malformed resource method")
            out.append((path, verb, method))
    return out


@install("aws.c2b.apigateway.domain_pqc_tls", "apigateway_domain_name", "API Gateway custom domain enforces a post-quantum TLS security policy",
         {"domainName": "api.example.com", "securityPolicy": "SecurityPolicy_TLS13_1_2_PQ_2025_09"}, {"domainName": "api.example.com", "securityPolicy": "TLS_1_2"},
         rows=[P + "apigateway_domain_name_pqc_tls_enabled"], severity="low", control="SC-13",
         remediation="Set the custom domain securityPolicy to a 2025-09 PQ policy such as SecurityPolicy_TLS13_1_2_PQ_2025_09.", docs=[D_DOMAIN, D_APIGW_TLS],
         note="Pinned prowler PQC_APIGATEWAY_POLICIES_DEFAULT = " + str(APIGW_PQC) + ".")
def apigw_domain_pqc(item, index):
    get(item, "domainName", str)
    policy = get(item, "securityPolicy", str)
    return result(policy not in APIGW_PQC, security_policy=policy, allowed=APIGW_PQC)


@install("aws.c2b.apigateway.authorizers_or_authorized_methods", "rest_api", "REST API has an authorizer or every non-OPTIONS method requires authorization",
         _rest(authorizers=[LAMBDA_AUTH]), _rest(authorizers=[], resources=[_resource("/", GET={"authorizationType": "NONE"})]),
         rows=[P + "apigateway_restapi_authorizers_enabled"], severity="medium", category="least_privilege", control="AC-3",
         remediation="Attach a Lambda or Cognito authorizer, or require IAM/custom authorization on every method.", docs=[D_AUTHORIZER, D_METHOD],
         extra={"iam_methods_pass": _rest(authorizers=[], resources=[_resource("/", GET={"authorizationType": "AWS_IAM"}, OPTIONS={"authorizationType": "NONE"})]),
                "no_methods": _rest(authorizers=[], resources=[_resource("/")]), "no_methods_expect": "FAIL"},
         note="Prowler semantics: OPTIONS methods are ignored and an API with no methods and no authorizer fails.")
def apigw_auth_or_methods(item, index):
    get(item, "id", str)
    authorizers = detail_list(item, "Authorizers")
    if authorizers:
        return result(False, authorizers=len(authorizers))
    methods = [(path, verb, get(m, "authorizationType", str)) for path, verb, m in _methods(item) if verb != "OPTIONS"]
    open_methods = [verb + " " + path for path, verb, kind in methods if kind == "NONE"]
    return result(not methods or bool(open_methods), authorizers=0, methods=len(methods), unauthorized_methods=open_methods)


@install("aws.c2b.apigateway.stage_cache_encrypted", "rest_api_stage", "REST API stage with caching encrypts cached data",
         _stage({"*/*": {"cachingEnabled": True, "cacheDataEncrypted": True}}), _stage({"*/*": {"cachingEnabled": True, "cacheDataEncrypted": False}}),
         rows=[P + "apigateway_restapi_cache_encrypted"], severity="medium", control="SC-28",
         remediation="Enable cacheDataEncrypted on the stage's method settings that enable caching.", docs=[D_STAGE, D_METHOD_SETTING],
         extra={"not_applicable": _stage({"*/*": {"cachingEnabled": False}})},
         note="Prowler: applies when any method setting enables caching; passes when any caching setting encrypts (aws.b.apigateway.wildcard_cache_encryption needs '*/*').")
def apigw_cache(item, index):
    caching = [v for v in _settings(item).values() if v.get("cachingEnabled")]
    if not caching:
        return "NOT_APPLICABLE", {"reason": "stage caching disabled"}
    encrypted = any(v.get("cacheDataEncrypted") for v in caching)
    return result(not encrypted, caching_settings=len(caching),
                  encrypted_cache_setting_found=encrypted,
                  observed="At least one cached method setting enables encryption." if encrypted else
                           "None of the cached method settings enables encryption.")


@install("aws.c2b.apigateway.stage_execution_logging", "rest_api_stage", "REST API stage has execution logging on some method setting",
         _stage({"*/*": {"loggingLevel": "ERROR"}}), _stage({"*/*": {"loggingLevel": "OFF"}}),
         rows=[P + "apigateway_restapi_logging_enabled"], severity="medium", control="AU-2",
         remediation="Set loggingLevel to ERROR or INFO in the stage method settings.", docs=[D_STAGE, D_METHOD_SETTING],
         extra={"no_settings": _stage(), "no_settings_expect": "FAIL"},
         note="Prowler: any method setting with a loggingLevel other than OFF passes (aws.b.apigateway.rest_execution_logging reads '*/*' only).")
def apigw_logging(item, index):
    levels = [v.get("loggingLevel") for v in _settings(item).values()]
    return result(not any(level and level != "OFF" for level in levels), logging_levels=levels)


@install("aws.c2b.apigateway.rest_api_private_only", "rest_api", "REST API endpoint type is PRIVATE only",
         _rest(("PRIVATE",)), _rest(("EDGE",)), rows=[P + "apigateway_restapi_public", X + "api_gateway_rest_api_prohibit_public_access"],
         severity="medium", category="exposure", control="SC-7",
         remediation="Use a PRIVATE endpoint reachable through an interface VPC endpoint when the API must not be internet-facing.", docs=[D_REST],
         note="Both sources compare endpointConfiguration.types with exactly [\"PRIVATE\"].")
def apigw_private(item, index):
    types = _types(item)
    return result(types != ["PRIVATE"], endpoint_types=types)


@install("aws.c2b.apigateway.public_rest_api_authorizer", "rest_api", "Public REST API has an authorizer",
         _rest(authorizers=[LAMBDA_AUTH]), _rest(authorizers=[]),
         rows=[P + "apigateway_restapi_public_with_authorizer", C + "api_gateway_rest_api_public_endpoint_with_authorizer"],
         severity="medium", category="least_privilege", control="AC-3",
         remediation="Attach a Lambda or Cognito authorizer to the public API (or make it PRIVATE).", docs=[D_AUTHORIZER, D_REST],
         extra={"not_applicable": _rest(("PRIVATE",), authorizers=[])},
         note="Any authorizer counts. Corrected for steampipe, which requires providerARNs: AWS documents providerARNs only for COGNITO_USER_POOLS, so Lambda (TOKEN/REQUEST) authorizers alarmed.")
def apigw_public_auth(item, index):
    types = _types(item)
    if types == ["PRIVATE"]:
        return "NOT_APPLICABLE", {"endpoint_types": types}
    authorizers = detail_list(item, "Authorizers")
    return result(not authorizers, endpoint_types=types, authorizers=len(authorizers))


@install("aws.c2b.apigateway.rest_api_has_authorizer", "rest_api", "REST API has at least one authorizer",
         _rest(authorizers=[{"id": "au2", "type": "COGNITO_USER_POOLS", "providerARNs": ["arn:aws:cognito-idp:us-east-1:" + ACCOUNT + ":userpool/p"]}]), _rest(authorizers=[]),
         rows=[C + "apigateway_rest_api_authorizers_configured"], severity="medium", category="least_privilege", control="AC-3",
         remediation="Attach a Lambda or Cognito authorizer to the API.", docs=[D_AUTHORIZER],
         extra={"lambda_pass": _rest(authorizers=[LAMBDA_AUTH])},
         note="Corrected: the pinned query requires providerARNs, which AWS documents only for COGNITO_USER_POOLS authorizers; any authorizer passes here.")
def apigw_has_auth(item, index):
    get(item, "id", str)
    authorizers = detail_list(item, "Authorizers")
    return result(not authorizers, authorizers=len(authorizers))


@install("aws.c2b.apigateway.methods_authorization_type", "rest_api", "REST API methods all declare an authorization type other than NONE",
         _rest(resources=[_resource("/", GET={"authorizationType": "CUSTOM", "authorizerId": "au1"})]),
         _rest(resources=[_resource("/", GET={"authorizationType": "AWS_IAM"}, OPTIONS={"authorizationType": "NONE"})]),
         rows=[C + "api_gateway_method_authorization_type_configured"], severity="medium", category="least_privilege", control="AC-3",
         remediation="Set authorizationType to AWS_IAM, CUSTOM or COGNITO_USER_POOLS on each method.", docs=[D_METHOD],
         extra={"not_applicable": _rest(resources=[_resource("/")])},
         note="Faithful to aws_api_gateway_method: every method including OPTIONS is evaluated.")
def apigw_method_auth(item, index):
    get(item, "id", str)
    methods = _methods(item)
    if not methods:
        return "NOT_APPLICABLE", {"reason": "API has no methods"}
    open_methods = [verb + " " + path for path, verb, m in methods if get(m, "authorizationType", str) == "NONE"]
    return result(bool(open_methods), methods_without_authorization=open_methods)


@install("aws.c2b.apigateway.methods_request_validator", "rest_api", "REST API methods all have a request validator",
         _rest(resources=[_resource("/", POST={"authorizationType": "AWS_IAM", "requestValidatorId": "v1"})]),
         _rest(resources=[_resource("/", POST={"authorizationType": "AWS_IAM"})]),
         rows=[C + "api_gateway_method_request_parameter_validated"], severity="medium", control="SI-10",
         remediation="Attach a request validator that validates parameters (and body) to each method.", docs=[D_METHOD],
         extra={"not_applicable": _rest(resources=[])})
def apigw_validator(item, index):
    get(item, "id", str)
    methods = _methods(item)
    if not methods:
        return "NOT_APPLICABLE", {"reason": "API has no methods"}
    missing = [verb + " " + path for path, verb, m in methods if not optional(m, "requestValidatorId", None, str)]
    return result(bool(missing), methods_without_validator=missing)


def _rest_policy(raw):
    try:
        return policy_document(raw)
    except Unavailable:
        if not isinstance(raw, str):
            raise
        return policy_document(raw.replace('\\"', '"'))


_PUBLIC_POLICY = '{\\"Version\\":\\"2012-10-17\\",\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Principal\\":\\"*\\",\\"Action\\":\\"execute-api:Invoke\\",\\"Resource\\":\\"*\\"}]}'
_VPCE_POLICY = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"*",'
                '"Condition":{"StringEquals":{"aws:SourceAccount":"' + ACCOUNT + '"}}}]}')


@install("aws.c2b.apigateway.rest_api_policy_not_public", "rest_api", "REST API resource policy does not allow unrestricted public invocation",
         _rest(policy=_VPCE_POLICY), _rest(policy=_PUBLIC_POLICY), rows=[X + "api_gateway_rest_api_policy_prohibit_public_access"],
         severity="medium", category="exposure", control="AC-3",
         remediation="Restrict the resource policy principal or add an aws:SourceAccount/aws:PrincipalOrgID/aws:SourceArn condition.", docs=[D_REST],
         extra={"no_policy": _rest()},
         note="aws-perimeter resource_policy_public_sql: Allow statement with a wildcard principal and no restricting condition. GetRestApis returns the policy as escaped JSON.")
def apigw_policy(item, index):
    get(item, "id", str)
    raw = optional(item, "policy", None)
    if raw is None:
        return result(False, policy=None)
    public = turbot_public_statements(_rest_policy(raw))
    return result(bool(public), public_statements=len(public))


# =========================================================================== API Gateway v2
def _http(authorizers=None, routes=None):
    item = {"ApiId": "h1", "Name": "http", "ProtocolType": "HTTP"}
    if authorizers is not None:
        item["Authorizers"] = {"collection_status": "collected" if authorizers else "empty", "items": list(authorizers)}
    if routes is not None:
        item["Routes"] = {"collection_status": "collected" if routes else "empty", "items": list(routes)}
    return item


def _route(key="GET /", auth=None, authorizer=None):
    row = {"RouteId": "rt" + str(len(key)), "RouteKey": key}
    if auth is not None:
        row["AuthorizationType"] = auth
    if authorizer is not None:
        row["AuthorizerId"] = authorizer
    return row


def _routes(item):
    get(item, "ApiId", str)
    return detail_list(item, "Routes")


@install("aws.c2b.apigatewayv2.api_has_authorizer", "http_api", "API Gateway v2 API has at least one authorizer",
         _http(authorizers=[{"AuthorizerId": "z1", "AuthorizerType": "JWT", "Name": "jwt"}]), _http(authorizers=[]),
         rows=[P + "apigatewayv2_api_authorizers_enabled"], severity="medium", category="least_privilege", control="AC-3",
         remediation="Attach a JWT or Lambda authorizer to the API.", docs=[D_V2_AUTH])
def apigw2_has_auth(item, index):
    get(item, "ApiId", str)
    authorizers = detail_list(item, "Authorizers")
    return result(not authorizers, authorizers=len(authorizers))


@install("aws.c2b.apigatewayv2.routes_authorization_type", "http_api", "API Gateway v2 routes all specify an authorization type",
         _http(routes=[_route(auth="JWT", authorizer="z1"), _route("$default", auth="AWS_IAM")]), _http(routes=[_route(auth="NONE")]),
         rows=[C + "api_gatewayv2_route_authorization_type_configured", C + "foundational_security_apigateway_8"], severity="medium", category="least_privilege", control="AC-3",
         remediation="Set AuthorizationType to AWS_IAM, CUSTOM or JWT on every route.", docs=[D_V2_ROUTE, "https://docs.aws.amazon.com/securityhub/latest/userguide/apigateway-controls.html#apigateway-8"],
         extra={"not_applicable": _http(routes=[]), "omitted": _http(routes=[_route()]), "omitted_expect": "FAIL"},
         note="Corrected per Security Hub APIGateway.8: GetRoutes returns AuthorizationType NONE for open routes (never null), so NONE or an omitted type fails.")
def apigw2_route_type(item, index):
    routes = _routes(item)
    if not routes:
        return "NOT_APPLICABLE", {"reason": "API has no routes"}
    open_routes = [get(r, "RouteKey", str) for r in routes if optional(r, "AuthorizationType", "NONE", str) == "NONE"]
    return result(bool(open_routes), routes_without_authorization=open_routes)


@install("aws.c2b.apigatewayv2.routes_authorizer", "http_api", "API Gateway v2 routes all reference an authorizer",
         _http(routes=[_route(auth="JWT", authorizer="z1")]), _http(routes=[_route(auth="JWT", authorizer="z1"), _route("$default", auth="AWS_IAM")]),
         rows=[C + "api_gatewayv2_route_authorizer_configured"], severity="medium", category="least_privilege", control="AC-3",
         remediation="Attach a JWT or Lambda authorizer to each route.", docs=[D_V2_ROUTE], extra={"not_applicable": _http(routes=[])},
         note="Faithful to the pinned query: a route without AuthorizerId alarms, including AWS_IAM routes.")
def apigw2_route_authorizer(item, index):
    routes = _routes(item)
    if not routes:
        return "NOT_APPLICABLE", {"reason": "API has no routes"}
    missing = [get(r, "RouteKey", str) for r in routes if not optional(r, "AuthorizerId", None, str)]
    return result(bool(missing), routes_without_authorizer=missing)


# =========================================================================== AppSync
def _gql(auth="AMAZON_COGNITO_USER_POOLS", level="ERROR", api_type=None, cache=None):
    item = {"apiId": "g1", "name": "gql", "arn": "arn:aws:appsync:us-east-1:" + ACCOUNT + ":apis/g1", "authenticationType": auth}
    if level is not None:
        item["logConfig"] = {"fieldLogLevel": level, "cloudWatchLogsRoleArn": "arn:aws:iam::" + ACCOUNT + ":role/l"}
    if api_type is not None:
        item["apiType"] = api_type
    if cache is not None:
        item["ApiCache"] = cache
    return item


def _cache(at_rest=True, transit=True):
    return {"collection_status": "collected", "apiCache": {"type": "SMALL", "status": "AVAILABLE", "atRestEncryptionEnabled": at_rest, "transitEncryptionEnabled": transit}}


@install("aws.c2b.appsync.field_level_logging", "appsync_graphql_api", "AppSync GraphQL API logs resolver fields at ERROR or ALL",
         _gql(level="ERROR"), _gql(level="NONE"),
         rows=[P + "appsync_field_level_logging_enabled", C + "appsync_graphql_api_field_level_logging_enabled", C + "foundational_security_appsync_2"],
         severity="medium", control="AU-2", remediation="Set logConfig.fieldLogLevel to ERROR or ALL.", docs=[D_APPSYNC],
         extra={"no_log_config": _gql(level=None), "no_log_config_expect": "FAIL"})
def appsync_logging(item, index):
    level = absent_or(item, "apiId", "logConfig.fieldLogLevel", "", str)
    return result(level not in ("ALL", "ERROR"), field_log_level=level or None)


@install("aws.c2b.appsync.graphql_no_api_key", "appsync_graphql_api", "AppSync GraphQL API does not use API_KEY default authentication",
         _gql(), _gql(auth="API_KEY"), rows=[P + "appsync_graphql_api_no_api_key_authentication"], severity="high", category="least_privilege", control="IA-2",
         remediation="Use AWS_IAM, Cognito user pools, OIDC or Lambda authorization instead of API keys.", docs=[D_APPSYNC],
         extra={"not_applicable": _gql(auth="API_KEY", api_type="MERGED")}, note="Prowler: only apiType GRAPHQL (the documented default when omitted) is evaluated.")
def appsync_api_key(item, index):
    api_type = absent_or(item, "apiId", "apiType", "GRAPHQL", str)
    if api_type != "GRAPHQL":
        return "NOT_APPLICABLE", {"api_type": api_type}
    auth = get(item, "authenticationType", str)
    return result(auth == "API_KEY", authentication_type=auth)


@install("aws.c2b.appsync.no_api_key_auth", "appsync_graphql_api", "AppSync API default authentication is not API_KEY",
         _gql(api_type="MERGED"), _gql(auth="API_KEY", api_type="MERGED"),
         rows=[C + "appsync_graphql_api_authentication_without_api_key", C + "foundational_security_appsync_5"], severity="medium", category="least_privilege", control="IA-2",
         remediation="Use AWS_IAM, Cognito user pools, OIDC or Lambda authorization instead of API keys.", docs=[D_APPSYNC],
         note="Steampipe evaluates every AppSync API regardless of apiType.")
def appsync_api_key_any(item, index):
    get(item, "apiId", str)
    auth = get(item, "authenticationType", str)
    return result(auth == "API_KEY", authentication_type=auth)


for _field, _suffix, _rows, _title in (
        ("atRestEncryptionEnabled", "cache_at_rest_encryption", [C + "appsync_graphql_api_cache_encryption_at_rest_enabled", C + "foundational_security_appsync_1"], "at rest"),
        ("transitEncryptionEnabled", "cache_in_transit_encryption", [C + "appsync_graphql_api_cache_encryption_in_transit_enabled", C + "foundational_security_appsync_6"], "in transit")):
    def _appsync_cache(field, suffix, rows, title):
        @install("aws.c2b.appsync." + suffix, "appsync_graphql_api", "AppSync API cache is encrypted " + title,
                 _gql(cache=_cache()), _gql(cache=_cache(**{("at_rest" if field.startswith("atRest") else "transit"): False})),
                 rows=rows, severity="medium", control="SC-28" if field.startswith("atRest") else "SC-8",
                 remediation="Recreate the API cache with " + field + " set to true.", docs=[D_APPSYNC_CACHE],
                 extra={"not_applicable": _gql(cache=dict(ABSENT))},
                 note="Corrected: an API without a cache (GetApiCache NotFoundException) is not applicable; the pinned query alarms on it.")
        def evaluate(item, index):
            get(item, "apiId", str)
            cache = detail(item, "ApiCache")
            if cache is None:
                return "NOT_APPLICABLE", {"reason": "API has no cache"}
            enabled = get(cache, "apiCache." + field, bool)
            return result(not enabled, **{field: enabled})
        return evaluate
    _appsync_cache(_field, _suffix, _rows, _title)


# =========================================================================== Direct Connect
def _conn(cid, location):
    return {"connectionId": cid, "connectionName": cid, "location": location, "connectionState": "available"}


def _vif(vid, connection, vgw="", dxgw=""):
    return {"virtualInterfaceId": vid, "connectionId": connection, "virtualGatewayId": vgw, "directConnectGatewayId": dxgw}


@install("aws.c2b.directconnect.connection_redundancy", "directconnect_connection", "Direct Connect has at least two connections in different locations",
         ANCHOR, ANCHOR, rows=[P + "directconnect_connection_redundancy"], severity="medium", category="network", control="CP-8", target="scope",
         dependencies=["directconnect_connection"], remediation="Provision a second Direct Connect connection at a different location.", docs=[D_DX_CONN, D_DX_RES],
         extra={"pass_index": inventory("directconnect_connection", [_conn("dxcon-1", "EqDC2"), _conn("dxcon-2", "CSVA1")]),
                "fail_index": inventory("directconnect_connection", [_conn("dxcon-1", "EqDC2"), _conn("dxcon-2", "EqDC2")]),
                "not_applicable_index": inventory("directconnect_connection", []), "not_applicable": ANCHOR,
                "single": ANCHOR, "single_index": inventory("directconnect_connection", [_conn("dxcon-1", "EqDC2")]), "single_expect": "FAIL"})
def dx_connections(item, index):
    scope = scope_of(item)
    rows = complete_items(index, "directconnect_connection")
    if not rows:
        return "NOT_APPLICABLE", {"scope": scope, "reason": "no Direct Connect connections"}
    locations = sorted({get(row, "location", str) for row in rows})
    return result(len(rows) < 2 or len(locations) < 2, scope=scope, connections=len(rows), locations=locations)


@install("aws.c2b.directconnect.virtual_interface_redundancy", "directconnect_virtual_interface",
         "Each virtual/Direct Connect gateway has at least two virtual interfaces on distinct connections",
         ANCHOR, ANCHOR, rows=[P + "directconnect_virtual_interface_redundancy"], severity="medium", category="network", control="CP-8", target="scope",
         dependencies=["directconnect_virtual_interface"], remediation="Add a second virtual interface on a different connection for every gateway.", docs=[D_DX_VIF, D_DX_RES],
         extra={"pass_index": inventory("directconnect_virtual_interface", [_vif("dxvif-1", "dxcon-1", dxgw="gw1"), _vif("dxvif-2", "dxcon-2", dxgw="gw1")]),
                "fail_index": inventory("directconnect_virtual_interface", [_vif("dxvif-1", "dxcon-1", vgw="vgw-1"), _vif("dxvif-2", "dxcon-1", vgw="vgw-1")]),
                "not_applicable_index": inventory("directconnect_virtual_interface", []), "not_applicable": ANCHOR},
         note="Corrected: distinct connections are counted (prowler appends a connection per VIF, so two VIFs on one connection passed).")
def dx_vifs(item, index):
    scope = scope_of(item)
    gateways = {}
    for row in complete_items(index, "directconnect_virtual_interface"):
        vif, connection = get(row, "virtualInterfaceId", str), get(row, "connectionId", str)
        for key in ("virtualGatewayId", "directConnectGatewayId"):
            gateway = optional(row, key, "", str)
            if gateway:
                entry = gateways.setdefault(gateway, {"vifs": set(), "connections": set()})
                entry["vifs"].add(vif)
                entry["connections"].add(connection)
    if not gateways:
        return "NOT_APPLICABLE", {"scope": scope, "reason": "no virtual interfaces attached to a gateway"}
    weak = sorted(g for g, e in gateways.items() if len(e["vifs"]) < 2 or len(e["connections"]) < 2)
    return result(bool(weak), scope=scope, gateways=len(gateways), non_redundant_gateways=weak)


# =========================================================================== Dispositions
_CF_NATIVE = "Pinned prowler predicate reads the same DistributionConfig field with the same empty-value failure as "
MERGED = {
    P + "cloudfront_distributions_default_root_object": (["aws.b.cloudfront.default_root_object"], _CF_NATIVE + "aws.b.cloudfront.default_root_object (DefaultRootObject == '' fails)."),
    P + "cloudfront_distributions_field_level_encryption_enabled": (["aws.b.cloudfront.field_level_encryption"], _CF_NATIVE + "aws.b.cloudfront.field_level_encryption (DefaultCacheBehavior.FieldLevelEncryptionId)."),
    P + "cloudfront_distributions_geo_restrictions_enabled": (["aws.b.cloudfront.geo_restrictions"], "Both fail exactly when Restrictions.GeoRestriction.RestrictionType is 'none'."),
    P + "cloudfront_distributions_using_waf": (["aws.b.cloudfront.waf_reference"], _CF_NATIVE + "aws.b.cloudfront.waf_reference (WebACLId == '' fails)."),
    C + "cloudfront_distribution_non_s3_origins_encryption_in_transit_enabled": (["aws.b.cloudfront.custom_origin_encryption"],
        "Same predicate: custom origins with http-only, or match-viewer while the default or any additional behavior allows HTTP, alarm; S3 origins are skipped."),
    P + "elb_connection_draining_enabled": (["aws.b.classic_elb.connection_draining"], "Both read Attributes.LoadBalancerAttributes.ConnectionDraining.Enabled."),
    P + "elb_cross_zone_load_balancing_enabled": (["aws.b.classic_elb.cross_zone"], "Both read Attributes.LoadBalancerAttributes.CrossZoneLoadBalancing.Enabled."),
    P + "elb_desync_mitigation_mode": (["aws.b.classic_elb.desync_mode"], "Both pass for elb.http.desyncmitigationmode defensive/strictest and fail for monitor."),
    P + "elb_is_in_multiple_az": (["aws.b.classic_elb.multiple_az"], "Both require more than one entry in AvailabilityZones."),
    P + "elb_logging_enabled": (["aws.b.classic_elb.access_logs"], "Both read Attributes.LoadBalancerAttributes.AccessLog.Enabled."),
    P + "apigateway_restapi_client_certificate_enabled": (["aws.b.apigateway.client_certificate"], "Both fail a REST stage without clientCertificateId."),
    P + "apigateway_restapi_tracing_enabled": (["aws.b.apigateway.rest_xray"], "Both fail a REST stage whose tracingEnabled is false."),
    P + "apigateway_restapi_waf_acl_attached": (["aws.b.apigateway.waf_reference"], "Both fail a REST stage without webAclArn."),
    P + "apigatewayv2_api_access_logging_enabled": (["aws.cb.apigatewayv2.stage_access_logging"], "Both fail an HTTP/WebSocket stage whose AccessLogSettings is absent or empty."),
}

MANUAL = {}

REJECTED = {
    P + "cloudfront_distributions_multiple_origin_failover_configured": {
        "classification": "invalid_predicate",
        "reason": "Prowler computes origin_failover = all(group.Members.Quantity >= 2 for group in OriginGroups.Items). AWS documents that an origin group always has "
                  "exactly two origins (primary and secondary), and all([]) is True when there are no origin groups, so the check can never FAIL. "
                  "aws.b.cloudfront.origin_group_metadata fails distributions without origin groups.",
        "replacement": ["aws.b.cloudfront.origin_group_metadata"],
        "docs": ["https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/high_availability_origin_failover.html"]},
    C + "foundational_security_cloudfront_13": {
        "classification": "invalid_predicate",
        "reason": "The control is 'CloudFront distributions should use origin access control', but the pinned query alarms when S3OriginConfig.OriginAccessIdentity is ''. "
                  "AWS requires an empty OriginAccessIdentity when OAC is used, so the query alarms on exactly the compliant configuration. "
                  "Corrected predicate: aws.c2b.cloudfront.s3_origin_access_control.",
        "replacement": ["aws.c2b.cloudfront.s3_origin_access_control"],
        "docs": [D_CF_S3, D_CF_OAC]},
    C + "elb_tls_listener_protocol_version": {
        "classification": "invalid_predicate",
        "reason": "The query alarms when an HTTPS listener's SslPolicy is like 'Protocol-SSLv3' or 'Protocol-TLSv1'. ELBv2 SslPolicy values are predefined "
                  "ELBSecurityPolicy-* names (no policy is named Protocol-*), so it never alarms. Replacement: aws.c2b.elbv2.insecure_ssl_ciphers.",
        "replacement": ["aws.c2b.elbv2.insecure_ssl_ciphers"],
        "docs": [D_ALB_POL, D_NLB_POL]},
    C + "elb_listener_use_secure_ssl_cipher": {
        "classification": "invalid_predicate",
        "reason": "Only ELBSecurityPolicy-TLS-1-2-2017-01 and ELBSecurityPolicy-TLS-1-1-2017-01 pass, and every listener without an SslPolicy (HTTP/TCP) alarms. "
                  "AWS recommends ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09 (the console default) and all TLS13 policies alarm, while the TLS 1.1 policy passes. "
                  "Replacement: aws.c2b.elbv2.insecure_ssl_ciphers.",
        "replacement": ["aws.c2b.elbv2.insecure_ssl_ciphers"],
        "docs": [D_ALB_POL]},
    C + "elb_network_lb_tls_listener_security_policy_configured": {
        "classification": "invalid_predicate",
        "reason": "Accepted TLS policies are ELBSecurityPolicy-2016-08 (supports TLS 1.0 and 1.1 per AWS), a misspelled 'ELBSecurityPolicy-FS-2018-0' and two TLS13 "
                  "policies; the AWS-recommended ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09 alarms while a TLS 1.0 policy passes. "
                  "Replacement: aws.c2b.elbv2.recommended_tls_policy (NLB TLS listeners).",
        "replacement": ["aws.c2b.elbv2.recommended_tls_policy"],
        "docs": [D_NLB_POL, D_ALB_POL]},
    P + "apigateway_restapi_no_secrets_in_stage_variables": {
        "classification": "intrusive_unsuitable",
        "reason": "Secret scanning of stage variable values: the collector deliberately strips stage 'variables' and PEASO does not read or retain secret material.",
        "replacement": [],
        "docs": ["https://docs.aws.amazon.com/apigateway/latest/developerguide/stage-variables.html"]},
}
