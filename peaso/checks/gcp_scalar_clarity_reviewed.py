"""Reviewed concise copy for twelve exact GCP scalar predicates.

Newly reviewed entries contain text only; no pending command is promoted.
"""
from copy import deepcopy

VERSION = "gcp-scalar-clarity-20261019"
ROWS = {'gcp.compute.integrity_monitoring': {'description_fields': {'description': 'Checks whether the VM declares '
                                                                            'Shielded VM integrity '
                                                                            'monitoring enabled.'},
                                      'remediation_fields': {'steps': ['Enable integrity monitoring in the '
                                                                       'VM’s Shielded VM settings.'],
                                                             'summary': 'Enable integrity monitoring in the '
                                                                        'VM’s Shielded VM settings.'}},
 'gcp.compute.secure_boot': {'description_fields': {'description': 'Checks whether the VM declares Secure '
                                                                   'Boot enabled.'},
                             'remediation_fields': {'steps': ['Enable Secure Boot after checking that the VM '
                                                              'kernel and drivers are signed and supported.'],
                                                    'summary': 'Enable Secure Boot after checking that the '
                                                               'VM kernel and drivers are signed and '
                                                               'supported.'}},
 'gcp.compute.shielded_vtpm': {'description_fields': {'description': 'Checks whether the VM declares its '
                                                                     'virtual TPM enabled.'},
                               'remediation_fields': {'steps': ['Enable vTPM in the VM’s Shielded VM '
                                                                'settings.'],
                                                      'summary': 'Enable vTPM in the VM’s Shielded VM '
                                                                 'settings.'}},
 'gcp.gke.secrets_encryption': {'description_fields': {'description': 'Compares the GKE cluster’s '
                                                                      'application-layer encryption state '
                                                                      'with ENCRYPTED; this is separate from '
                                                                      'Google’s default storage encryption.'},
                                'remediation_fields': {'caveats': ['Only the recorded setting is evaluated; '
                                                                   'supported configuration and runtime '
                                                                   'behavior must be checked separately.'],
                                                       'cli': [],
                                                       'references': [{'title': 'GKE application-layer '
                                                                                'Secrets encryption',
                                                                       'url': 'https://cloud.google.com/kubernetes-engine/docs/how-to/encrypting-secrets'}],
                                                       'review_status': 'approved',
                                                       'steps': ['Enable application-layer Secrets '
                                                                 'encryption with a Cloud KMS key and grant '
                                                                 'the GKE service agent access to that key.'],
                                                       'summary': 'Enable application-layer Secrets '
                                                                  'encryption with a Cloud KMS key and grant '
                                                                  'the GKE service agent access to that '
                                                                  'key.'}},
 'gcp.network.custom_subnets': {'description_fields': {'description': 'Checks whether the VPC uses custom '
                                                                      'subnet mode instead of automatically '
                                                                      'creating regional subnets.'},
                                'remediation_fields': {'steps': ['Review the existing subnets and routes, '
                                                                 'then convert this VPC to custom mode; '
                                                                 'conversion cannot be reversed.'],
                                                       'summary': 'Review the existing subnets and routes, '
                                                                  'then convert this VPC to custom mode; '
                                                                  'conversion cannot be reversed.'}},
 'gcp.reviewed.compute.automatic_restart': {'description_fields': {'description': 'Checks whether automatic '
                                                                                  'restart after a host '
                                                                                  'failure is enabled; it '
                                                                                  'does not test '
                                                                                  'availability.'},
                                            'remediation_fields': {'steps': ['Enable automatic restart if '
                                                                             'this VM should restart after a '
                                                                             'host failure.'],
                                                                   'summary': 'Enable automatic restart if '
                                                                              'this VM should restart after '
                                                                              'a host failure.'}},
 'gcp.reviewed.compute.confidential_computing': {'description_fields': {'description': 'Checks whether the '
                                                                                       'VM declares '
                                                                                       'Confidential '
                                                                                       'Computing enabled; '
                                                                                       'it does not attest '
                                                                                       'the running VM.'},
                                                 'remediation_fields': {'caveats': ['Only the recorded '
                                                                                    'setting is evaluated; '
                                                                                    'supported configuration '
                                                                                    'and runtime behavior '
                                                                                    'must be checked '
                                                                                    'separately.'],
                                                                        'cli': [],
                                                                        'references': [{'title': 'Create a '
                                                                                                 'Confidential '
                                                                                                 'VM',
                                                                                        'url': 'https://cloud.google.com/confidential-computing/confidential-vm/docs/create-a-confidential-vm-instance'}],
                                                                        'review_status': 'approved',
                                                                        'steps': ['Use a supported '
                                                                                  'Confidential VM '
                                                                                  'configuration if this '
                                                                                  'workload requires '
                                                                                  'confidential computing.'],
                                                                        'summary': 'Use a supported '
                                                                                   'Confidential VM '
                                                                                   'configuration if this '
                                                                                   'workload requires '
                                                                                   'confidential '
                                                                                   'computing.'}},
 'gcp.reviewed.compute.deletion_protection': {'description_fields': {'description': 'Checks whether the VM '
                                                                                    'declares deletion '
                                                                                    'protection enabled.'},
                                              'remediation_fields': {'steps': ['Enable deletion protection '
                                                                               'for VMs that should be '
                                                                               'protected from accidental '
                                                                               'deletion.'],
                                                                     'summary': 'Enable deletion protection '
                                                                                'for VMs that should be '
                                                                                'protected from accidental '
                                                                                'deletion.'}},
 'gcp.reviewed.compute.maintenance_migrate': {'description_fields': {'description': 'Checks whether the VM’s '
                                                                                    'host maintenance policy '
                                                                                    'is MIGRATE; hardware '
                                                                                    'and workload support '
                                                                                    'are not evaluated.'},
                                              'remediation_fields': {'caveats': ['Only the recorded setting '
                                                                                 'is evaluated; supported '
                                                                                 'configuration and runtime '
                                                                                 'behavior must be checked '
                                                                                 'separately.'],
                                                                     'cli': [],
                                                                     'references': [{'title': 'VM host '
                                                                                              'maintenance '
                                                                                              'policy',
                                                                                     'url': 'https://cloud.google.com/compute/docs/instances/setting-vm-host-options'}],
                                                                     'review_status': 'approved',
                                                                     'steps': ['Use MIGRATE for VMs that '
                                                                               'support live migration; '
                                                                               'retain TERMINATE where the '
                                                                               'VM type requires it.'],
                                                                     'summary': 'Use MIGRATE for VMs that '
                                                                                'support live migration; '
                                                                                'retain TERMINATE where the '
                                                                                'VM type requires it.'}},
 'gcp.reviewed.loadbalancer.backend_logging': {'description_fields': {'description': 'Checks whether logging '
                                                                                     'is enabled on the load '
                                                                                     'balancer backend '
                                                                                     'service; it does not '
                                                                                     'verify log delivery or '
                                                                                     'completeness.'},
                                               'remediation_fields': {'caveats': ['Only the recorded setting '
                                                                                  'is evaluated; supported '
                                                                                  'configuration and runtime '
                                                                                  'behavior must be checked '
                                                                                  'separately.'],
                                                                      'cli': [],
                                                                      'references': [{'title': 'Load '
                                                                                               'balancer '
                                                                                               'logging',
                                                                                      'url': 'https://cloud.google.com/load-balancing/docs/https/https-logging-monitoring'}],
                                                                      'review_status': 'approved',
                                                                      'steps': ['Enable logging on this '
                                                                                'backend service and choose '
                                                                                'a sample rate suited to the '
                                                                                'traffic you need to '
                                                                                'record.'],
                                                                      'summary': 'Enable logging on this '
                                                                                 'backend service and choose '
                                                                                 'a sample rate suited to '
                                                                                 'the traffic you need to '
                                                                                 'record.'}},
 'gcp.sql.backups': {'description_fields': {'description': 'Checks whether automated backups are enabled for '
                                                           'the Cloud SQL instance; it does not test '
                                                           'restoration or point-in-time recovery.'},
                     'remediation_fields': {'steps': ['Enable automated backups for this Cloud SQL '
                                                      'instance.'],
                                            'summary': 'Enable automated backups for this Cloud SQL '
                                                       'instance.'}},
 'gcp.sql.no_public_ip': {'description_fields': {'description': 'Checks whether public IPv4 is disabled on '
                                                                'the Cloud SQL instance; it does not test '
                                                                'database access.'},
                          'remediation_fields': {'steps': ['Move intended clients to private connectivity '
                                                           'before disabling public IPv4.'],
                                                 'summary': 'Move intended clients to private connectivity '
                                                            'before disabling public IPv4.'}}}
def _apply(check_id, original, kind):
    row = ROWS.get(check_id)
    if row is None:
        return deepcopy(original)
    current = deepcopy(original) if isinstance(original, dict) else {}
    current.update(deepcopy(row[kind + "_fields"]))
    return current


def description(check_id, original):
    return _apply(check_id, original, "description")


def remediation(check_id, original):
    return _apply(check_id, original, "remediation")


REVIEWED_RISKS = {
    "gcp.compute.shielded_vtpm": ("medium", "medium"),
    "gcp.compute.integrity_monitoring": ("medium", "medium"),
    "gcp.compute.secure_boot": ("medium", "medium"),
    "gcp.sql.backups": ("medium", "medium"),
    "gcp.sql.no_public_ip": ("medium", "medium"),
    "gcp.gke.secrets_encryption": ("medium", "low"),
    "gcp.network.custom_subnets": ("medium", "low"),
    "gcp.reviewed.compute.deletion_protection": ("medium", "low"),
    "gcp.reviewed.compute.automatic_restart": ("medium", "low"),
    "gcp.reviewed.compute.maintenance_migrate": ("medium", "info"),
    "gcp.reviewed.compute.confidential_computing": ("medium", "low"),
    "gcp.reviewed.loadbalancer.backend_logging": ("medium", "medium"),
}
