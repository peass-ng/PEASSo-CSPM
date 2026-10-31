"""One source-reviewed criteria erratum; native SG predicates stay unchanged."""
from copy import deepcopy

CHECK_ID = 'aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis'
VERSION = 'aws-sg-any-port-description-20261021-v1'
BASE_ROW_SHA256 = '33fa9afe7b6d4535d68c120c26369b4e5a83795e1035eb2ac35f78d3e8f5a147'
SOURCE_REVISION = '7f9eb2cb11ea931f54acccb6e49152358ccf949d'
SOURCE_ROOT = 'https://github.com/prowler-cloud/prowler/blob/' + SOURCE_REVISION + '/prowler/providers/aws/services/ec2/'
SOURCE_URL = SOURCE_ROOT + 'ec2_securitygroup_allow_ingress_from_internet_to_any_port/ec2_securitygroup_allow_ingress_from_internet_to_any_port.py'
HELPER_URL = SOURCE_ROOT + 'lib/security_groups.py'
FIELDS = {
    'description': 'Checks any internet-open port on in-use security groups with customer-managed ENIs; a single TCP 22 rule from 0.0.0.0/0 or ::/0 qualifies. API Gateway, VPC endpoint and amazon-elb interfaces are exempt. Reachability is not tested.',
    'pass_when': 'For an in-use group, no matching world-source ingress exists, or every attached ENI is api_gateway_managed, vpc_endpoint, or owned by amazon-elb.',
    'fail_when': 'For an in-use group, any matching ingress rule from 0.0.0.0/0 or ::/0 (including a single TCP or UDP port, such as TCP 22) exists and at least one attached ENI is neither api_gateway_managed nor vpc_endpoint and is not owned by amazon-elb. Opening every port is not required.',
}


def description(original):
    current = deepcopy(original) if isinstance(original, dict) else {}
    current.update(FIELDS)
    current['description_correction'] = {
        'version': VERSION, 'base_row_sha256': BASE_ROW_SHA256,
        'source_revision': SOURCE_REVISION, 'source_url': SOURCE_URL, 'helper_url': HELPER_URL,
        'source_relationship': 'Corrects descriptive all-ports prose to the existing any-port predicate. With an empty ports list, all_ports=True accepts a single matching ingress port; evaluator and managed-interface exceptions are unchanged. Frozen description history is retained.',
    }
    return current
