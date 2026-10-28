# GCP official product sweep — 2026-10-27

Inventory source: [Google Cloud product list](https://docs.cloud.google.com/docs/product-list), retrieved 2026-10-27, supplemented with Firebase Realtime Database because its rules are an independent exposure surface. The table is a tracking inventory, not a closure claim. `REVIEW REQUIRED` means an independent exposure primitive has not yet been ruled out or implemented.

Open review ledger: **178 rows** remain REVIEW REQUIRED; **115 have no native path identified** in this sweep and **63 have a partial native path**. The rows below name every open product. By category, the counts are Cross-product tools 14, AI and ML 18, App development 23, App hosting 5, Compute 12, Data analytics and pipelines 17, Databases 11, Distributed/hybrid/multicloud 6, Industry solutions 7, Migration 6, Networking 23, Observability 5, Security 27, and Storage 4. A dash in the native-path column means no product-specific native path has yet been identified; it is not an API impossibility or a concrete data blocker. A populated native path is still REVIEW REQUIRED until that product's public endpoints, IAM/policy/ACL, sharing, and federation primitives have been exhaustively checked.

| Category | Product | Native path found so far | Audit state |
| --- | --- | --- | --- |
| Cross-product tools | [Access Approval](https://docs.cloud.google.com/assured-workloads/access-approval/docs) | — | REVIEW REQUIRED |
| Cross-product tools | [Cloud Billing](https://docs.cloud.google.com/billing/docs) | — | REVIEW REQUIRED |
| Cross-product tools | [Cloud Hub](https://docs.cloud.google.com/hub/docs) | — | REVIEW REQUIRED |
| Cross-product tools | [Cloud Identity](https://docs.cloud.google.com/identity/docs) | — | REVIEW REQUIRED |
| Cross-product tools | [Cloud Marketplace](https://docs.cloud.google.com/marketplace/docs) | — | REVIEW REQUIRED |
| Cross-product tools | [Cloud Quotas](https://docs.cloud.google.com/docs/quotas) | — | REVIEW REQUIRED |
| Cross-product tools | [Config Connector](https://docs.cloud.google.com/config-connector/docs) | — | REVIEW REQUIRED |
| Cross-product tools | [gcloud CLI](https://docs.cloud.google.com/sdk/gcloud) | — | REVIEW REQUIRED |
| Cross-product tools | [Identity Platform](https://docs.cloud.google.com/identity-platform/docs) | identityplatform_tenant / identityplatform_config anonymous sign-up / IAM | REVIEW REQUIRED |
| Cross-product tools | [Infra Manager](https://docs.cloud.google.com/infrastructure-manager/docs) | — | REVIEW REQUIRED |
| Cross-product tools | [Managed Microsoft AD](https://docs.cloud.google.com/managed-microsoft-ad/docs) | managed_ad_domain trust direction / authorizedNetworks | REVIEW REQUIRED |
| Cross-product tools | [Recommender](https://docs.cloud.google.com/recommender/docs) | — | REVIEW REQUIRED |
| Cross-product tools | [Service Catalog](https://docs.cloud.google.com/service-catalog/docs) | — | REVIEW REQUIRED |
| Cross-product tools | [Service Usage](https://docs.cloud.google.com/service-usage/docs) | — | REVIEW REQUIRED |
| AI and ML | [Agent Platform Vision](https://docs.cloud.google.com/vision-ai/docs) | — | REVIEW REQUIRED |
| AI and ML | [Cloud TPU](https://docs.cloud.google.com/tpu/docs) | tpu_node external IP, endpoint port, target tags/service account and shared-VPC networkConfigs firewall join; distinct-VPC selection uses an explicit single public-enabled VPC or a unique endpoint internal-IP match to every bound subnet CIDR; a contradictory collected subnet match keeps the path UNKNOWN; ambiguous or missing subnet facts leave association unresolved | REVIEW REQUIRED |
| AI and ML | [Colab Enterprise](https://docs.cloud.google.com/colab/docs) | — | REVIEW REQUIRED |
| AI and ML | [Deep Learning Containers](https://docs.cloud.google.com/deep-learning-containers/docs) | — | REVIEW REQUIRED |
| AI and ML | [Deep Learning VM](https://docs.cloud.google.com/deep-learning-vm/docs) | — | REVIEW REQUIRED |
| AI and ML | [Dialogflow ES](https://docs.cloud.google.com/dialogflow/es/docs) | — | REVIEW REQUIRED |
| AI and ML | [DocAI](https://docs.cloud.google.com/document-ai/docs) | — | REVIEW REQUIRED |
| AI and ML | [Enterprise Knowledge Graph](https://docs.cloud.google.com/enterprise-knowledge-graph/docs) | — | REVIEW REQUIRED |
| AI and ML | [Gemini Enterprise Agent Platform](https://docs.cloud.google.com/gemini-enterprise-agent-platform) | workbench_instance Jupyter proxy URI, disableProxyAccess and ACTIVE state; identity grants, direct VM ingress and other Agent Platform interfaces unresolved | REVIEW REQUIRED |
| AI and ML | [Live Stream API](https://docs.cloud.google.com/livestream/docs) | — | REVIEW REQUIRED |
| AI and ML | [Speech-to-Text](https://docs.cloud.google.com/speech-to-text/docs) | — | REVIEW REQUIRED |
| AI and ML | [TensorFlow Enterprise](https://docs.cloud.google.com/tensorflow-enterprise/docs) | — | REVIEW REQUIRED |
| AI and ML | [Text-to-Speech](https://docs.cloud.google.com/text-to-speech/docs) | — | REVIEW REQUIRED |
| AI and ML | [Transcoder API](https://docs.cloud.google.com/transcoder/docs) | — | REVIEW REQUIRED |
| AI and ML | [Translation](https://docs.cloud.google.com/translate/docs) | — | REVIEW REQUIRED |
| AI and ML | [Video Intelligence API](https://docs.cloud.google.com/video-intelligence/docs) | — | REVIEW REQUIRED |
| AI and ML | [Video Stitcher API](https://docs.cloud.google.com/video-stitcher/docs) | — | REVIEW REQUIRED |
| AI and ML | [Vision API](https://docs.cloud.google.com/vision/docs) | — | REVIEW REQUIRED |
| App development | [API Gateway](https://docs.cloud.google.com/api-gateway/docs) | api_gateway | REVIEW REQUIRED |
| App development | [Apigee](https://docs.cloud.google.com/apigee/docs) | — | REVIEW REQUIRED |
| App development | [App Design Center](https://docs.cloud.google.com/application-design-center/docs) | — | REVIEW REQUIRED |
| App development | [App Hub](https://docs.cloud.google.com/app-hub/docs) | — | REVIEW REQUIRED |
| App development | [Application Integration](https://docs.cloud.google.com/application-integration/docs) | — | REVIEW REQUIRED |
| App development | [Artifact Analysis](https://docs.cloud.google.com/artifact-analysis/docs) | — | REVIEW REQUIRED |
| App development | [Artifact Registry](https://docs.cloud.google.com/artifact-registry/docs) | artifact_repository direct public Reader IAM grant and generic public IAM; inherited/custom roles, mode and artifacts unresolved | REVIEW REQUIRED |
| App development | [Cloud Build](https://docs.cloud.google.com/build/docs) | cloudbuild_connection direct cross-project Viewer/Admin IAM grant; SCM provider, host URI, private Service Directory path and token-reference fields are dropped by the current collector projection, so linked repository/token path needs a reviewed source update | REVIEW REQUIRED |
| App development | [Cloud Code](https://docs.cloud.google.com/code/docs) | — | REVIEW REQUIRED |
| App development | [Cloud Deploy](https://docs.cloud.google.com/deploy/docs) | clouddeploy_delivery_pipeline direct cross-project Releaser IAM declaration; inherited IAM, release/rollout and target effects unresolved | REVIEW REQUIRED |
| App development | [Cloud Scheduler](https://docs.cloud.google.com/scheduler/docs) | scheduler_job enabled HTTP target with configured OIDC token; ownership, delivery and other target paths unresolved | REVIEW REQUIRED |
| App development | [Cloud Shell](https://docs.cloud.google.com/shell/docs) | — | REVIEW REQUIRED |
| App development | [Cloud Source Repositories](https://docs.cloud.google.com/source-repositories/docs) | source_repository direct cross-project Reader IAM grant; inherited/custom roles and ownership unresolved | REVIEW REQUIRED |
| App development | [Cloud Tasks](https://docs.cloud.google.com/tasks/docs) | cloudtasks_queue direct cross-project Enqueuer IAM grant; queue HTTP override is reduced to a boolean, collector projection has a reviewed-source hash gate, and task targets remain unjoined | REVIEW REQUIRED |
| App development | [Cloud Workstations](https://docs.cloud.google.com/workstations/docs) | workstation / workstation_cluster | REVIEW REQUIRED |
| App development | [Developer Connect](https://docs.cloud.google.com/developer-connect/docs) | developerconnect_git_repository_link recorded Git proxy HTTPS origin yields UNKNOWN pending identity grants, connection state, repository permissions and response; collector omits clone URI and most connection settings | REVIEW REQUIRED |
| App development | [Developer Device Platform](https://docs.cloud.google.com/developer-device-platform) | — | REVIEW REQUIRED |
| App development | [Eventarc](https://docs.cloud.google.com/eventarc/docs) | eventarc_message_bus direct public or cross-project Message Bus User publish IAM grant; cross-project eventarc_enrollment bus-to-pipeline route is UNKNOWN; inherited/custom roles, IAM denies, CEL filters, pipeline targets, delivery and consumer behavior unresolved | REVIEW REQUIRED |
| App development | [Integration Connectors](https://docs.cloud.google.com/integration-connectors/docs) | — | REVIEW REQUIRED |
| App development | [Secure Source Manager](https://docs.cloud.google.com/secure-source-manager/docs) | secure_source_instance ACTIVE HTTP service attachment with explicit additional numeric PSC consumer project; consumer endpoint, routes, instance/repository IAM and ownership unresolved; selected collector omits isPrivate and hostConfig, blocking public endpoint decision | REVIEW REQUIRED |
| App development | [Service Infrastructure](https://docs.cloud.google.com/service-infrastructure/docs) | — | REVIEW REQUIRED |
| App development | [Software supply chain security](https://docs.cloud.google.com/software-supply-chain-security/docs) | — | REVIEW REQUIRED |
| App development | [Workflows](https://docs.cloud.google.com/workflows/docs) | workflows_workflow cross-project serviceAccount declaration; sourceContents, effective attachment permissions and outbound targets unresolved | REVIEW REQUIRED |
| App hosting | [App Engine](https://docs.cloud.google.com/appengine/docs) | app_engine_application default hostname and serving status; ordered ingress firewall evaluator accepts complete cached rule facts, but the current collector cannot fetch them under its reviewed whole-file source gate, so serving applications without those facts remain UNKNOWN; IAP and custom-domain joins remain | REVIEW REQUIRED |
| App hosting | [Blockchain Node Engine](https://docs.cloud.google.com/blockchain-node-engine/docs) | blockchain_node | REVIEW REQUIRED |
| App hosting | [Buildpacks](https://docs.cloud.google.com/docs/buildpacks) | — | REVIEW REQUIRED |
| App hosting | [Cloud Run](https://docs.cloud.google.com/run/docs) | cloudrun_service / function v2 backing-service ingress and IAM; cloudrun_instance serving URLs, public ingress and direct invoker grant or disabled check; IAP, inherited IAM, custom domains and other routes unresolved | REVIEW REQUIRED |
| App hosting | [Google Kubernetes Engine (GKE)](https://docs.cloud.google.com/kubernetes-engine/docs) | gke_cluster / Kubernetes snapshot | REVIEW REQUIRED |
| Compute | [AI Hypercomputer](https://docs.cloud.google.com/ai-hypercomputer/docs) | — | REVIEW REQUIRED |
| Compute | [Batch](https://docs.cloud.google.com/batch/docs) | batch_network_job RUNNING with explicit noExternalIpAddress false and no recorded instance-template override records UNKNOWN external-IP eligibility; actual VM IP, effective firewall, listener and response unresolved | REVIEW REQUIRED |
| Compute | [Capacity Planner](https://docs.cloud.google.com/capacity-planner/docs) | — | REVIEW REQUIRED |
| Compute | [Cluster Director](https://docs.cloud.google.com/cluster-director/docs) | — | REVIEW REQUIRED |
| Compute | [Cluster Toolkit](https://docs.cloud.google.com/cluster-toolkit/docs) | — | REVIEW REQUIRED |
| Compute | [Compute Engine](https://docs.cloud.google.com/compute/docs) | instance / per-interface effective firewall with ordered hierarchy, regional system-to-network, explicit BEFORE_CLASSIC global-to-regional transitions, and default/explicit AFTER_CLASSIC positive classic allows, including a client outside earlier narrow denies with or without attached policies, or provably nonmatching classic transitions into network policy / forwarding_rule; other policy decisions remain | REVIEW REQUIRED |
| Compute | [Container-Optimized OS](https://docs.cloud.google.com/container-optimized-os/docs) | — | REVIEW REQUIRED |
| Compute | [Oracle on Google Cloud Compute](https://docs.cloud.google.com/oracle/compute) | — | REVIEW REQUIRED |
| Compute | [Shielded VMs](https://docs.cloud.google.com/compute/shielded-vm/docs) | — | REVIEW REQUIRED |
| Compute | [VM Manager](https://docs.cloud.google.com/compute/vm-manager/docs) | — | REVIEW REQUIRED |
| Compute | [VMware Engine](https://docs.cloud.google.com/vmware-engine/docs) | vmware_external_address / network policy / ordered external access rules; NSX controls outside Google API | REVIEW REQUIRED |
| Compute | [Workload Manager](https://docs.cloud.google.com/workload-manager/docs) | — | REVIEW REQUIRED |
| Data analytics and pipelines | [BigQuery](https://docs.cloud.google.com/bigquery/docs) | dataset legacy ACL / cross-project grants / scheduled authorized views, routine IAM and project-inherited and direct custom-role reader joins | REVIEW REQUIRED |
| Data analytics and pipelines | [Blockchain Analytics](https://docs.cloud.google.com/blockchain-analytics/docs) | — | REVIEW REQUIRED |
| Data analytics and pipelines | [Cloud Data Fusion](https://docs.cloud.google.com/data-fusion/docs) | data_fusion_instance | REVIEW REQUIRED |
| Data analytics and pipelines | [Cortex Framework](https://docs.cloud.google.com/cortex/docs) | — | REVIEW REQUIRED |
| Data analytics and pipelines | [Data Studio](https://docs.cloud.google.com/data-studio) | — | REVIEW REQUIRED |
| Data analytics and pipelines | [Dataflow](https://docs.cloud.google.com/dataflow/docs) | dataflow_network_job RUNNING with WORKER_IP_PUBLIC worker pool records UNKNOWN public-IP configuration; assigned VM address, effective firewall, listener and data access unresolved | REVIEW REQUIRED |
| Data analytics and pipelines | [Dataform](https://docs.cloud.google.com/dataform/docs) | — | REVIEW REQUIRED |
| Data analytics and pipelines | [Dataproc Metastore](https://docs.cloud.google.com/dataproc-metastore/docs) | — | REVIEW REQUIRED |
| Data analytics and pipelines | [Datastream](https://docs.cloud.google.com/datastream/docs) | datastream_private_connection CREATED PSC interface to a different explicit project network attachment records UNKNOWN; attachment acceptance, route, stream/profile, source credentials and data transfer unresolved; CREATED cross-project VPC peering with a /29 range is also UNKNOWN pending exchanged routes and source access | REVIEW REQUIRED |
| Data analytics and pipelines | [Knowledge Catalog](https://docs.cloud.google.com/dataplex/docs) | — | REVIEW REQUIRED |
| Data analytics and pipelines | [Lakehouse](https://docs.cloud.google.com/lakehouse/docs) | — | REVIEW REQUIRED |
| Data analytics and pipelines | [Looker](https://docs.cloud.google.com/looker/docs) | looker_instance | REVIEW REQUIRED |
| Data analytics and pipelines | [Managed Service for Apache Airflow](https://docs.cloud.google.com/composer/docs) | composer_environment Airflow URI and web-server IP allowlist, with a present empty control object blocking public UI clients; IAM and other interfaces unresolved | REVIEW REQUIRED |
| Data analytics and pipelines | [Managed Service for Apache Kafka](https://docs.cloud.google.com/managed-service-for-apache-kafka/docs) | managed_kafka_cluster ACTIVE publicClusterConfig with globally routable IPv4 allowedSourceIpRanges records UNKNOWN; external addresses when present, TLS/IAM or mTLS authentication, topic ACL and message access unresolved; ACTIVE different-project private subnet is UNKNOWN pending service-agent IAM, route, authentication and topic ACL joins; other private paths remain | REVIEW REQUIRED |
| Data analytics and pipelines | [Managed Service for Apache Spark](https://docs.cloud.google.com/managed-spark/docs) | dataproc_cluster Component Gateway HTTPS URLs and enabled state; IAM grants, UI response, underlying VM exposure and other interfaces unresolved | REVIEW REQUIRED |
| Data analytics and pipelines | [Manufacturing Data Engine](https://docs.cloud.google.com/manufacturing-data-engine/docs) | — | REVIEW REQUIRED |
| Data analytics and pipelines | [Pub/Sub](https://docs.cloud.google.com/pubsub/docs) | Topic public Publisher and subscription public Subscriber direct IAM grants; subscription OIDC push endpoint configuration; inherited/custom roles, IAM denies, conditions, endpoint ownership and successful message access unresolved | REVIEW REQUIRED |
| Databases | [AlloyDB](https://docs.cloud.google.com/alloydb/docs) | alloydb_instance public IP / Data API executeSql declaration; collected PSC service attachment and different numeric allowedConsumerProjects produce UNKNOWN, while ACTIVE cross-project pscAutoConnections records a created internal endpoint; routes, IAM and database joins remain unresolved | REVIEW REQUIRED |
| Databases | [AlloyDB Omni](https://docs.cloud.google.com/alloydb/omni/docs) | — | REVIEW REQUIRED |
| Databases | [Bigtable](https://docs.cloud.google.com/bigtable/docs) | bigtable_table direct cross-project Reader IAM grant; other scopes, roles and ownership unresolved | REVIEW REQUIRED |
| Databases | [Cloud SQL](https://docs.cloud.google.com/sql/docs) | sql_instance public IPv4 and authorized-network direct engine port or authenticated connector TCP 3307; connectorEnforcement REQUIRED suppresses direct-port attribution despite retained authorized networks; an authorized-network expiration is evaluated at snapshot creation time with nanosecond precision; IAM, database credentials and successful connection unresolved | REVIEW REQUIRED |
| Databases | [Database Migration Service](https://docs.cloud.google.com/database-migration/docs) | migration_private_connection CREATED PSC interface to a different explicit project network attachment records UNKNOWN; acceptance, route, migration job, source credentials and data transfer unresolved; CREATED different-project VPC peering with a valid /29 is also UNKNOWN pending exchanged routes and source access | REVIEW REQUIRED |
| Databases | [Firestore in Datastore mode](https://docs.cloud.google.com/datastore/docs) | IAM policy / Firebase rules releases where applicable | REVIEW REQUIRED |
| Databases | [Firestore with MongoDB compatibility](https://docs.cloud.google.com/firestore/mongodb-compatibility/docs) | — | REVIEW REQUIRED |
| Databases | [Firebase Realtime Database](https://firebase.google.com/docs/database/security) | firebase_database_rules read-only instance/rules inventory; public/authenticated/conditional flags | REVIEW REQUIRED |
| Databases | [Memorystore for Redis Cluster](https://docs.cloud.google.com/memorystore/docs/cluster) | redis_cluster ACTIVE user-registered PSC discovery/primary/reader endpoint in a different explicit consumer project records UNKNOWN; route, authorization/ACL, data and other endpoint joins unresolved | REVIEW REQUIRED |
| Databases | [Memorystore for Valkey](https://docs.cloud.google.com/memorystore/docs/valkey) | memorystore_instance ACTIVE user-registered PSC discovery/primary/reader endpoint in a different explicit consumer project records UNKNOWN; route, authorization/ACL, data and other endpoint joins unresolved | REVIEW REQUIRED |
| Databases | [Spanner](https://docs.cloud.google.com/spanner/docs) | — | REVIEW REQUIRED |
| Distributed, hybrid, and multicloud | [Cloud Location Finder](https://docs.cloud.google.com/location-finder/docs) | — | REVIEW REQUIRED |
| Distributed, hybrid, and multicloud | [Config Controller](https://docs.cloud.google.com/kubernetes-engine/config-controller/docs) | — | REVIEW REQUIRED |
| Distributed, hybrid, and multicloud | [Config Sync](https://docs.cloud.google.com/kubernetes-engine/config-sync/docs) | — | REVIEW REQUIRED |
| Distributed, hybrid, and multicloud | [GKE Multi-Cloud](https://docs.cloud.google.com/kubernetes-engine/multi-cloud/docs) | — | REVIEW REQUIRED |
| Distributed, hybrid, and multicloud | [Policy Controller](https://docs.cloud.google.com/kubernetes-engine/policy-controller/docs) | — | REVIEW REQUIRED |
| Distributed, hybrid, and multicloud | [Service Directory](https://docs.cloud.google.com/service-directory/docs) | — | REVIEW REQUIRED |
| Industry solutions | [AI Commerce Search](https://docs.cloud.google.com/retail/docs) | — | REVIEW REQUIRED |
| Industry solutions | [Anti Money Laundering AI (AML AI)](https://docs.cloud.google.com/financial-services/anti-money-laundering/docs) | — | REVIEW REQUIRED |
| Industry solutions | [Healthcare Data Engine](https://docs.cloud.google.com/healthcare-api/docs) | — | REVIEW REQUIRED |
| Industry solutions | [Talent Solutions](https://docs.cloud.google.com/talent-solution/job-search/docs) | — | REVIEW REQUIRED |
| Industry solutions | [Telecom Network Automation](https://docs.cloud.google.com/telecom-network-automation/docs) | — | REVIEW REQUIRED |
| Industry solutions | [Telecom Subscriber Insights API](https://docs.cloud.google.com/telecom-subscriber-insights/docs) | — | REVIEW REQUIRED |
| Industry solutions | [Vision API Product Search](https://docs.cloud.google.com/vision/product-search/docs) | — | REVIEW REQUIRED |
| Migration | [Dual Run](https://docs.cloud.google.com/mainframe-dual-run/docs) | — | REVIEW REQUIRED |
| Migration | [Mainframe Assessment Tool](https://docs.cloud.google.com/mainframe-assessment-tool/docs) | — | REVIEW REQUIRED |
| Migration | [Mainframe Connector](https://docs.cloud.google.com/mainframe-connector/docs) | — | REVIEW REQUIRED |
| Migration | [Migrate to Containers](https://docs.cloud.google.com/migrate/containers/docs) | — | REVIEW REQUIRED |
| Migration | [Migrate to VMs](https://docs.cloud.google.com/migrate/virtual-machines/docs/5.0) | — | REVIEW REQUIRED |
| Migration | [Migration Center](https://docs.cloud.google.com/migration-center/docs) | — | REVIEW REQUIRED |
| Networking | [Cloud Armor](https://docs.cloud.google.com/armor/docs) | security_policy | REVIEW REQUIRED |
| Networking | [Cloud CDN](https://docs.cloud.google.com/cdn/docs) | backend bucket origin and private service-agent IAM join; direct bucket/project public object-get, complete public object ACL or public managed-folder object-get on a top-level (including unmatched exact-host HTTP) or bound matcher default route; backend-service edge/backend Cloud Armor cache-path distinction; top-level defaults require unmatched Host and path matchers require bound host rules; a selected path-rule Host/path can join a direct public bucket/project object-get grant or an unmodified object path under a public managed folder; other object routes and origin grants unresolved | REVIEW REQUIRED |
| Networking | [Cloud DNS](https://docs.cloud.google.com/dns/docs) | dns_managed_zone public visibility joined to dns_record_set static, weighted, geographic and primary/backup routing A/AAAA public addresses, including health-checked external endpoints; exact public address can identify a unique same-project external forwarding rule; forwarding-rule-backed health targets, delegation, other address owners, network and IAM joins unresolved | REVIEW REQUIRED |
| Networking | [Cloud Domains](https://docs.cloud.google.com/domains/docs) | domains_registration direct cross-project Admin/Editor IAM DNS-configuration declaration; current dnsSettings omitted, effective IAM and changes unresolved | REVIEW REQUIRED |
| Networking | [Cloud IDS](https://docs.cloud.google.com/intrusion-detection-system/docs) | — | REVIEW REQUIRED |
| Networking | [Cloud Interconnect](https://docs.cloud.google.com/network-connectivity/docs/interconnect) | interconnect_attachment Dedicated or Partner VLAN with ACTIVE state, OS_ACTIVE operation, adminEnabled true and Cloud Router recorded as UNKNOWN; BGP, routes, remote ownership, firewall and workload access unresolved | REVIEW REQUIRED |
| Networking | [Cloud Load Balancing](https://docs.cloud.google.com/load-balancing/docs) | forwarding_rule / target proxy / URL map / backend service or bucket / edge policy; private-only forwarding sourceIpRanges block public clients, and one narrow subset can join a sole effective target-instance or single target-pool VM ingress allow on the same client and port; target-pool delivery uses nic0, target-instance delivery uses nic0 or its explicit project-qualified VPC's unique interface, and a first matching CLOUD_ARMOR_NETWORK deny on a target instance or pool blocks unresolved narrow paths when its source CIDRs contain every admitted forwarding source and its destination-address, protocol and destination-port selectors cover the forwarding traffic; an earlier edge rule with source CIDRs disjoint from every admitted forwarding CIDR or destination CIDRs disjoint from the forwarding address/prefix, or an exact IP protocol different from the sole forwarded protocol, or destination ports disjoint from every forwarded TCP/UDP port, cannot shadow a later full-coverage deny; other narrow source subsets need downstream client witnesses; URL-map default/path including unmatched exact-host HTTP default, first prefix-or-exact-path and later disjoint exact-path route-rule redirects without a backend; first bound wildcard-host universal route-rule backend even with later unreachable rules, and first-priority exact/prefix and later path-disjoint exact/prefix-path backend witnesses, including unshadowed subdomain wildcard Hosts; selected exact/suffix path-rule backend Host/path witness, including an unshadowed subdomain wildcard Host, with universal sole wildcard-Host `/*` backend Cloud Armor block; other route and policy joins unresolved | REVIEW REQUIRED |
| Networking | [Cloud NAT](https://docs.cloud.google.com/nat/docs) | router.nats Public NAT with selected subnet ranges and automatic or allocated manual external IPs records UNKNOWN outbound translation; NAT cannot admit unsolicited inbound traffic, while workload destinations, routes, egress firewall and data transfer remain unresolved | REVIEW REQUIRED |
| Networking | [Cloud NGFW](https://docs.cloud.google.com/firewall/docs) | per-interface effective firewall / ordered hierarchy, regional system, classic VPC and global/regional network positive subcases, including a terminal narrow public-CIDR allow and a surviving public client after multiple narrow policy or classic VPC denies; advanced selectors and remaining policy precedence unresolved | REVIEW REQUIRED |
| Networking | [Cloud Router](https://docs.cloud.google.com/network-connectivity/docs/router) | router explicit enabled CUSTOM BGP ALL_SUBNETS or named CIDR advertisement recorded as UNKNOWN; session, remote peer, accepted/return routes, firewall and workload access unresolved | REVIEW REQUIRED |
| Networking | [Cloud Service Mesh](https://docs.cloud.google.com/service-mesh/docs) | — | REVIEW REQUIRED |
| Networking | [Cloud VPN](https://docs.cloud.google.com/network-connectivity/docs/vpn) | public HA VPN interface IPs and classic target-VPN forwarding rules declare IKE/ESP endpoint protocols; ESTABLISHED HA tunnels join their exact public gateway interface and configured external peer gateway reference, and Classic tunnels join public peer IP plus same-IP ESP/UDP forwarding triplet; cross-project peerGcpGateway tunnels also join the exact local HA interface; peer ownership, same-project tunnel paths, route and post-decap firewall joins unresolved | REVIEW REQUIRED |
| Networking | [Data Transfer Essentials](https://docs.cloud.google.com/data-transfer-essentials/docs) | — | REVIEW REQUIRED |
| Networking | [Media CDN](https://docs.cloud.google.com/media-cdn/docs) | media_cdn_service | REVIEW REQUIRED |
| Networking | [Network Connectivity Center (NCC)](https://docs.cloud.google.com/network-connectivity/docs/network-connectivity-center) | ACTIVE cross-project network_connectivity_spoke linked to a VPC and hub records UNKNOWN; hub topology, route filters, other spokes, firewall and workload access unresolved | REVIEW REQUIRED |
| Networking | [Network Intelligence Center](https://docs.cloud.google.com/network-intelligence-center/docs) | — | REVIEW REQUIRED |
| Networking | [Network Security Integration](https://docs.cloud.google.com/network-security-integration/docs) | — | REVIEW REQUIRED |
| Networking | [Network Service Tiers](https://docs.cloud.google.com/network-tiers/docs) | — | REVIEW REQUIRED |
| Networking | [Secure Access Connect](https://docs.cloud.google.com/secure-access-connect/docs) | — | REVIEW REQUIRED |
| Networking | [Secure Web Proxy](https://docs.cloud.google.com/secure-web-proxy/docs) | — | REVIEW REQUIRED |
| Networking | [Service Extensions](https://docs.cloud.google.com/service-extensions/docs) | — | REVIEW REQUIRED |
| Networking | [Virtual Private Cloud (VPC)](https://docs.cloud.google.com/vpc/docs) | active cross-project peerings from cached network.peerings produce UNKNOWN pending effective exchanged routes, destination firewall and peer ownership; VPC NAT, Shared VPC and other route paths unresolved | REVIEW REQUIRED |
| Networking | [VPC Service Controls](https://docs.cloud.google.com/vpc-service-controls/docs) | enforced regular service_perimeter wildcard ANY_IDENTITY ingress from accessLevel * to resources * and serviceName * records UNKNOWN; IAM, actual request and data access unresolved | REVIEW REQUIRED |
| Observability and monitoring | [Error Reporting](https://docs.cloud.google.com/error-reporting/docs) | — | REVIEW REQUIRED |
| Observability and monitoring | [Logging](https://docs.cloud.google.com/logging/docs) | Enabled sink destination naming a different project ID; destination ownership, writer IAM, filters/exclusions, project-number aliases and delivery unresolved | REVIEW REQUIRED |
| Observability and monitoring | [Monitoring](https://docs.cloud.google.com/monitoring/docs) | — | REVIEW REQUIRED |
| Observability and monitoring | [Profiler](https://docs.cloud.google.com/profiler/docs) | — | REVIEW REQUIRED |
| Observability and monitoring | [Trace](https://docs.cloud.google.com/trace/docs) | — | REVIEW REQUIRED |
| Security | [Access Context Manager](https://docs.cloud.google.com/access-context-manager/docs) | — | REVIEW REQUIRED |
| Security | [Access Transparency](https://docs.cloud.google.com/assured-workloads/access-transparency/docs) | — | REVIEW REQUIRED |
| Security | [Advisory Notifications](https://docs.cloud.google.com/advisory-notifications/docs) | — | REVIEW REQUIRED |
| Security | [Assured OSS](https://docs.cloud.google.com/assured-open-source-software/docs) | — | REVIEW REQUIRED |
| Security | [Assured Workloads](https://docs.cloud.google.com/assured-workloads/docs) | — | REVIEW REQUIRED |
| Security | [Audit Manager](https://docs.cloud.google.com/audit-manager/docs) | — | REVIEW REQUIRED |
| Security | [Binary Authorization](https://docs.cloud.google.com/binary-authorization/docs) | — | REVIEW REQUIRED |
| Security | [CA Service](https://docs.cloud.google.com/certificate-authority-service/docs) | ca_pool direct cross-project Certificate Requester IAM declaration; issuance policy, CA state, inherited IAM and actual issuance unresolved | REVIEW REQUIRED |
| Security | [Certificate Manager](https://docs.cloud.google.com/certificate-manager/docs) | — | REVIEW REQUIRED |
| Security | [Chrome Enterprise Premium](https://docs.cloud.google.com/chrome-enterprise-premium/docs) | — | REVIEW REQUIRED |
| Security | [Cloud Asset Inventory](https://docs.cloud.google.com/asset-inventory/docs) | — | REVIEW REQUIRED |
| Security | [Cloud KMS](https://docs.cloud.google.com/kms/docs) | Direct cross-project key Decrypter grants; key-ring/ancestor and custom roles, IAM denies, key-version state and successful decryption unresolved | REVIEW REQUIRED |
| Security | [Fraud Defense](https://docs.cloud.google.com/recaptcha/docs) | — | REVIEW REQUIRED |
| Security | [Google SecOps](https://docs.cloud.google.com/chronicle/docs) | — | REVIEW REQUIRED |
| Security | [Identity and Access Management (IAM)](https://docs.cloud.google.com/iam/docs) | principal exposure / workload identity provider to service-account IAM binding | REVIEW REQUIRED |
| Security | [Identity-Aware Proxy](https://docs.cloud.google.com/iap/docs) | iap_tunnel_policy direct instance-level cross-project Tunnel User IAM declaration; inherited policy, VM firewall, destination port and guest listener unresolved | REVIEW REQUIRED |
| Security | [Model Armor](https://docs.cloud.google.com/model-armor) | — | REVIEW REQUIRED |
| Security | [Policy Intelligence](https://docs.cloud.google.com/policy-intelligence/docs) | — | REVIEW REQUIRED |
| Security | [Resource Manager](https://docs.cloud.google.com/resource-manager/docs) | — | REVIEW REQUIRED |
| Security | [Secret Manager](https://docs.cloud.google.com/secret-manager/docs) | Direct cross-project service-account Secret Accessor grant; account ownership, inherited/custom roles, IAM denies, version state and successful payload access unresolved | REVIEW REQUIRED |
| Security | [Security Command Center](https://docs.cloud.google.com/security-command-center/docs) | — | REVIEW REQUIRED |
| Security | [Sensitive Data Protection](https://docs.cloud.google.com/sensitive-data-protection/docs) | — | REVIEW REQUIRED |
| Security | [Service Health](https://docs.cloud.google.com/service-health/docs) | — | REVIEW REQUIRED |
| Security | [Sovereign Controls by Partners](https://docs.cloud.google.com/sovereign-controls-by-partners/docs) | — | REVIEW REQUIRED |
| Security | [Spectrum Access System](https://docs.cloud.google.com/spectrum-access-system/docs) | — | REVIEW REQUIRED |
| Security | [Unified Maintenance](https://docs.cloud.google.com/unified-maintenance/docs) | — | REVIEW REQUIRED |
| Security | [Web Risk](https://docs.cloud.google.com/web-risk/docs) | — | REVIEW REQUIRED |
| Storage | [Backup and DR Service](https://docs.cloud.google.com/backup-disaster-recovery/docs) | — | REVIEW REQUIRED |
| Storage | [Cloud Storage](https://docs.cloud.google.com/storage/docs) | bucket / ACL / managed-folder IAM / effective ancestor IAM with hydrated custom roles / PAP / IP filter / Firebase Storage rules releases | REVIEW REQUIRED |
| Storage | [Filestore](https://docs.cloud.google.com/filestore/docs) | filestore_instance READY NFS share with explicit globally routable export source CIDR records UNKNOWN on private VPC endpoint; remote route, client authentication, mount and file contents unresolved | REVIEW REQUIRED |
| Storage | [NetApp Volumes](https://docs.cloud.google.com/netapp/volumes/docs) | netapp_volume READY NFS export with explicit globally routable allowedClients CIDR and read/write access mode records UNKNOWN; VPC route, NFS authentication, mount and file contents unresolved | REVIEW REQUIRED |
