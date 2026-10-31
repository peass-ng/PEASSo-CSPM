"""Individually source-reviewed AWS compute/storage finding guidance. No cloud operations."""
from copy import deepcopy
import json

VERSION = "aws-compute-storage-clarity-20261019"
ROWS = json.loads(r'''
{
  "aws.claude_a.ebs.attached_volume_encrypted": {
    "description_fields": {
      "description": "For in-use volumes, reads the Encrypted flag."
    },
    "remediation_fields": {
      "summary": "If encryption is required, plan a supported encrypted-copy migration while preserving needed data.",
      "steps": [
        "If encryption is required, plan a supported encrypted-copy migration while preserving needed data."
      ],
      "caveats": [
        "Other volume states are not applicable; no disk data is read."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached EBS volume declares encryption disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ebs_volume",
      "predicate_qualname": "ebs_attached_encrypted",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ebs.attached_delete_on_termination": {
    "description_fields": {
      "description": "For in-use volumes, requires nonempty attachments with DeleteOnTermination=true."
    },
    "remediation_fields": {
      "summary": "Set deletion-on-termination only for data that should be removed with the instance.",
      "steps": [
        "Set deletion-on-termination only for data that should be removed with the instance."
      ],
      "caveats": [
        "Persistent data may intentionally outlive an instance; other volume states are not applicable."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "At least one volume attachment lacks deletion-on-termination.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ebs_volume",
      "predicate_qualname": "ebs_attached_dot",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ebs.volume_in_use": {
    "description_fields": {
      "description": "Compares the EBS volume state with in-use."
    },
    "remediation_fields": {
      "summary": "Review the volume\u2019s recovery purpose and owner before retaining or retiring unused storage.",
      "steps": [
        "Review the volume\u2019s recovery purpose and owner before retaining or retiring unused storage."
      ],
      "caveats": [
        "An available volume can be intentional recovery storage; this is not evidence of public data."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EBS volume is not in the in-use state.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ebs_volume",
      "predicate_qualname": "ebs_in_use",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ebs.volume_has_snapshot": {
    "description_fields": {
      "description": "Joins the volume ID to self-owned snapshot VolumeId values."
    },
    "remediation_fields": {
      "summary": "Configure suitable snapshots or backups and verify recovery when required.",
      "steps": [
        "Configure suitable snapshots or backups and verify recovery when required."
      ],
      "caveats": [
        "Snapshot existence does not establish freshness or restore success."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No snapshot with the volume\u2019s ID is present in the complete snapshot inventory.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ebs_volume",
      "predicate_qualname": "ebs_has_snapshot",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ebs.volume_protected_by_backup": {
    "description_fields": {
      "description": "Matches the regional volume ARN to EBS records in AWS Backup protected resources."
    },
    "remediation_fields": {
      "summary": "Configure intended backup protection and verify required recovery points.",
      "steps": [
        "Configure intended backup protection and verify required recovery points."
      ],
      "caveats": [
        "This checks the protected-resource inventory, not every backup plan or recovery outcome."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The volume has no matching AWS Backup protected-resource record.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ebs_volume",
      "predicate_qualname": "ebs_protected",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ebs.volume_in_backup_selection": {
    "description_fields": {
      "description": "Matches the volume ARN or any volume tag key against Backup selection entries."
    },
    "remediation_fields": {
      "summary": "Configure the intended Backup resource assignment and verify its actual selection.",
      "steps": [
        "Configure the intended Backup resource assignment and verify its actual selection."
      ],
      "caveats": [
        "Tag values, operators, exclusions and effective selection are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The volume matches neither an exact selection ARN nor a listed tag key.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ebs_volume",
      "predicate_qualname": "ebs_in_selection",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ebs.volume_in_backup_plan_resources": {
    "description_fields": {
      "description": "Matches the volume ARN, the EC2 volume wildcard or * in Backup selection Resources."
    },
    "remediation_fields": {
      "summary": "Add the required supported resource assignment and verify actual backup coverage.",
      "steps": [
        "Add the required supported resource assignment and verify actual backup coverage."
      ],
      "caveats": [
        "Tag-based selection and completed recovery points are not assessed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No exact or supported wildcard volume ARN occurs in Backup selection Resources.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ebs_volume",
      "predicate_qualname": "ebs_in_plan_resources",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ebs.snapshot_encrypted": {
    "description_fields": {
      "description": "Reads the snapshot Encrypted flag."
    },
    "remediation_fields": {
      "summary": "If needed, create and validate an encrypted snapshot copy before retiring the old copy.",
      "steps": [
        "If needed, create and validate an encrypted snapshot copy before retiring the old copy."
      ],
      "caveats": [
        "Sharing, contents and recovery success are separate."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EBS snapshot declares encryption disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ebs_snapshot",
      "predicate_qualname": "snapshot_encrypted",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ebs.snapshot_not_public": {
    "description_fields": {
      "description": "Checks create-volume permissions for Group=all without a UserId."
    },
    "remediation_fields": {
      "summary": "Remove unintended public restore permission while retaining required account-specific sharing.",
      "steps": [
        "Remove unintended public restore permission while retaining required account-specific sharing."
      ],
      "caveats": [
        "This is a declared public restore permission, not a completed restore."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EBS snapshot permits the all group to create volumes.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "ebs_snapshot",
      "predicate_qualname": "snapshot_public",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.ebs_encryption_by_default": {
    "description_fields": {
      "description": "Reads the regional EBS encryption-by-default flag."
    },
    "remediation_fields": {
      "summary": "Enable the intended encryption default for future EBS storage and review existing volumes separately.",
      "steps": [
        "Enable the intended encryption default for future EBS storage and review existing volumes separately."
      ],
      "caveats": [
        "Existing volumes are not reconfigured by this default."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "EBS encryption by default is disabled in this Region.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ec2_regional_settings",
      "predicate_qualname": "ebs_default_encryption",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.ebs_encryption_by_default_with_volumes": {
    "description_fields": {
      "description": "In Regions with volumes, reads the EBS encryption-by-default flag."
    },
    "remediation_fields": {
      "summary": "Enable the intended encryption default for future EBS storage and review existing volumes separately.",
      "steps": [
        "Enable the intended encryption default for future EBS storage and review existing volumes separately."
      ],
      "caveats": [
        "Regions without volumes are not applicable; current volume encryption is separate."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "EBS encryption by default is disabled in a Region containing volumes.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ec2_regional_settings",
      "predicate_qualname": "ebs_default_encryption_used",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.snapshot_block_public_access": {
    "description_fields": {
      "description": "In Regions with snapshots, compares snapshot public-access blocking with block-all-sharing."
    },
    "remediation_fields": {
      "summary": "Choose the intended public-sharing protection and separately review existing shares.",
      "steps": [
        "Choose the intended public-sharing protection and separately review existing shares."
      ],
      "caveats": [
        "Regions without snapshots are not applicable; block-new-sharing fails this stronger baseline."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Snapshot public-access protection is not set to block-all-sharing.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ec2_regional_settings",
      "predicate_qualname": "snapshot_bpa",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.ami_block_public_access": {
    "description_fields": {
      "description": "Compares the regional AMI public-access setting with block-new-sharing."
    },
    "remediation_fields": {
      "summary": "Block new public AMI sharing unless public image distribution is intended.",
      "steps": [
        "Block new public AMI sharing unless public image distribution is intended."
      ],
      "caveats": [
        "This default does not inventory or revoke existing public image permissions."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "AMI public-access blocking is unblocked.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ec2_regional_settings",
      "predicate_qualname": "ami_bpa",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.account_imdsv2_default": {
    "description_fields": {
      "description": "In Regions with instances, checks regional metadata defaults for HttpTokens=required."
    },
    "remediation_fields": {
      "summary": "Require IMDSv2 in intended launch defaults and separately review existing instances.",
      "steps": [
        "Require IMDSv2 in intended launch defaults and separately review existing instances."
      ],
      "caveats": [
        "Regions without instances are not applicable; account defaults do not prove existing instance settings."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Regional instance-metadata defaults do not explicitly require IMDSv2 tokens.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ec2_regional_settings",
      "predicate_qualname": "account_imdsv2",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.ami_not_public": {
    "description_fields": {
      "description": "Reads Public on account-owned AMIs."
    },
    "remediation_fields": {
      "summary": "Remove unintended public image sharing while preserving deliberate public distributions.",
      "steps": [
        "Remove unintended public image sharing while preserving deliberate public distributions."
      ],
      "caveats": [
        "This does not inspect the image\u2019s contents or an actual launch."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The account-owned AMI is declared public.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "ec2_image",
      "predicate_qualname": "ami_public",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.ami_ebs_encrypted": {
    "description_fields": {
      "description": "Checks every AMI block mapping for Ebs.Encrypted=true."
    },
    "remediation_fields": {
      "summary": "If encryption is required, create and validate a supported encrypted image copy.",
      "steps": [
        "If encryption is required, create and validate a supported encrypted image copy."
      ],
      "caveats": [
        "No mappings is not applicable; instance-store mappings fail this particular EBS-only criterion."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "At least one AMI block mapping does not declare encrypted EBS storage.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ec2_image",
      "predicate_qualname": "ami_encrypted",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.ami_not_older_than_90_days": {
    "description_fields": {
      "description": "Compares AMI creation with midnight UTC ninety days before the snapshot."
    },
    "remediation_fields": {
      "summary": "Review image support and patch status; rebuild outdated images when needed.",
      "steps": [
        "Review image support and patch status; rebuild outdated images when needed."
      ],
      "caveats": [
        "Image creation age alone does not establish installed patch versions or vulnerabilities."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The AMI was created before the ninety-day cutoff.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ec2_image",
      "predicate_qualname": "ami_age",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_detailed_monitoring": {
    "description_fields": {
      "description": "Reads instance Monitoring.State and requires enabled."
    },
    "remediation_fields": {
      "summary": "Enable detailed monitoring if the workload needs one-minute metrics.",
      "steps": [
        "Enable detailed monitoring if the workload needs one-minute metrics."
      ],
      "caveats": [
        "Basic monitoring and alternative observability are not assessed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Detailed EC 2 monitoring is not declared enabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_monitoring",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_ebs_optimized": {
    "description_fields": {
      "description": "Reads whether the instance declares EBS optimization enabled."
    },
    "remediation_fields": {
      "summary": "Use appropriate EBS performance settings where required by the workload.",
      "steps": [
        "Use appropriate EBS performance settings where required by the workload."
      ],
      "caveats": [
        "This is a performance preference, not proof of insecure storage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The instance is not declared EBS-optimized.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_ebs_optimized",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_profile_attached": {
    "description_fields": {
      "description": "Checks whether IamInstanceProfile is present."
    },
    "remediation_fields": {
      "summary": "Attach a suitable least-privilege instance profile only if the workload needs AWS API access.",
      "steps": [
        "Attach a suitable least-privilege instance profile only if the workload needs AWS API access."
      ],
      "caveats": [
        "Instance-profile presence does not prove appropriate grants or absence of static credentials."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No IAM instance profile is declared on the applicable instance.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_profile",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_profile_attached_not_terminated": {
    "description_fields": {
      "description": "For non-terminated instances, checks whether IamInstanceProfile is present."
    },
    "remediation_fields": {
      "summary": "Attach a suitable least-privilege instance profile only if the workload needs AWS API access.",
      "steps": [
        "Attach a suitable least-privilege instance profile only if the workload needs AWS API access."
      ],
      "caveats": [
        "Terminated instances are not applicable; profile grants and credential use are not resolved."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No IAM instance profile is declared on the applicable instance.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_profile_live",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_in_vpc": {
    "description_fields": {
      "description": "Checks whether a VpcId is declared on the instance."
    },
    "remediation_fields": {
      "summary": "Use the intended supported VPC networking design when migrating legacy workloads.",
      "steps": [
        "Use the intended supported VPC networking design when migrating legacy workloads."
      ],
      "caveats": [
        "This checks metadata, not traffic filtering or actual routing."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The instance has no VPC ID declaration.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_in_vpc",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_no_public_ip": {
    "description_fields": {
      "description": "Checks whether a public IPv4 address is declared."
    },
    "remediation_fields": {
      "summary": "Remove unnecessary public addressing while preserving intended public services.",
      "steps": [
        "Remove unnecessary public addressing while preserving intended public services."
      ],
      "caveats": [
        "A public address does not prove a route, open listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A public IPv4 address is declared on the instance.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_public",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_no_public_ip_not_terminated": {
    "description_fields": {
      "description": "For non-terminated instances, checks whether a public IPv4 address is declared."
    },
    "remediation_fields": {
      "summary": "Remove unnecessary public addressing while preserving intended public services.",
      "steps": [
        "Remove unnecessary public addressing while preserving intended public services."
      ],
      "caveats": [
        "Terminated instances are not applicable; routes and listeners are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A public IPv4 address is declared on the instance.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_public_live",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.public_instance_has_profile": {
    "description_fields": {
      "description": "For instances declaring public IPv4, checks whether an IAM instance profile is present."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Configure a suitable profile if the publicly addressed workload needs AWS access.",
      "steps": [
        "Configure a suitable profile if the publicly addressed workload needs AWS access."
      ],
      "caveats": [
        "Instances without public IPv4 are not applicable; a profile is not proof of least privilege."
      ],
      "cli": [],
      "references": [
        {
          "title": "Amazon EC2 read-only API reference",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Welcome.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The publicly addressed instance declares no IAM instance profile.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_public_profile",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.internet_facing_without_profile": {
    "description_fields": {
      "description": "For non-terminated instances, flags the combination of public IPv4 and an instance profile."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Review public addressing and the profile\u2019s required permissions before changing either.",
      "steps": [
        "Review public addressing and the profile\u2019s required permissions before changing either."
      ],
      "caveats": [
        "A public address plus role is not proof of exposed metadata or a usable escalation path."
      ],
      "cli": [],
      "references": [
        {
          "title": "Amazon EC2 read-only API reference",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Welcome.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The instance declares both a public IPv4 address and an IAM instance profile.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_internet_profile",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.running_instance_no_key_pair": {
    "description_fields": {
      "description": "For running instances, checks whether KeyName is declared."
    },
    "remediation_fields": {
      "summary": "Use the intended managed access method; retire unnecessary long-lived key-pair access safely.",
      "steps": [
        "Use the intended managed access method; retire unnecessary long-lived key-pair access safely."
      ],
      "caveats": [
        "Non-running instances are not applicable; a launch key name does not prove current SSH access."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The running instance declares an EC 2 key-pair name.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_key_pair",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_imdsv2_applied": {
    "description_fields": {
      "description": "Requires HttpTokens=required and metadata-option State=applied."
    },
    "remediation_fields": {
      "summary": "Require IMDSv2 for intended workloads and verify the metadata change is applied.",
      "steps": [
        "Require IMDSv2 for intended workloads and verify the metadata change is applied."
      ],
      "caveats": [
        "The metadata endpoint\u2019s reachability from a process is not probed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Instance metadata tokens are not required or the settings are not applied.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_imdsv2_applied",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_imdsv2_or_disabled": {
    "description_fields": {
      "description": "For non-terminated instances, requires tokens on enabled metadata endpoints or accepts a disabled endpoint."
    },
    "remediation_fields": {
      "summary": "Require IMDSv2 or disable unnecessary metadata access after checking workload requirements.",
      "steps": [
        "Require IMDSv2 or disable unnecessary metadata access after checking workload requirements."
      ],
      "caveats": [
        "Terminated instances are not applicable; metadata access paths are not exercised."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The applicable metadata endpoint is not declared disabled or enabled with required tokens.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_imdsv2_prowler",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_protected_by_backup": {
    "description_fields": {
      "description": "Matches the instance ARN to EC2 records in AWS Backup protected resources."
    },
    "remediation_fields": {
      "summary": "Configure required backup protection and verify suitable recovery points.",
      "steps": [
        "Configure required backup protection and verify suitable recovery points."
      ],
      "caveats": [
        "Alternative backup mechanisms and restore success are not assessed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The instance has no matching AWS Backup protected-resource record.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_backup",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_no_launch_wizard_sg": {
    "description_fields": {
      "description": "Looks for attached security-group names beginning with launch-wizard."
    },
    "remediation_fields": {
      "summary": "Review the group\u2019s rules and replace or narrow unnecessary access as appropriate.",
      "steps": [
        "Review the group\u2019s rules and replace or narrow unnecessary access as appropriate."
      ],
      "caveats": [
        "A group name alone does not establish permissive rules or network exposure."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security-group name begins with launch-wizard.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_launch_wizard",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_not_paravirtual": {
    "description_fields": {
      "description": "Checks the instance VirtualizationType for the legacy paravirtual value."
    },
    "remediation_fields": {
      "summary": "Plan a supported HVM migration if the workload no longer needs legacy virtualization.",
      "steps": [
        "Plan a supported HVM migration if the workload no longer needs legacy virtualization."
      ],
      "caveats": [
        "Virtualization type alone does not establish an exploitable vulnerability."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The applicable instance declares paravirtual virtualization.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_paravirtual",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_not_paravirtual_not_terminated": {
    "description_fields": {
      "description": "For non-terminated instances, compares VirtualizationType with paravirtual."
    },
    "remediation_fields": {
      "summary": "Plan a supported HVM migration if the workload no longer needs legacy virtualization.",
      "steps": [
        "Plan a supported HVM migration if the workload no longer needs legacy virtualization."
      ],
      "caveats": [
        "Terminated instances are not applicable; patch support requires separate review."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The applicable instance declares paravirtual virtualization.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_paravirtual_live",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_termination_protection": {
    "description_fields": {
      "description": "Reads the instance DisableApiTermination protection flag and requires true."
    },
    "remediation_fields": {
      "summary": "Enable termination protection where accidental instance deletion must be prevented.",
      "steps": [
        "Enable termination protection where accidental instance deletion must be prevented."
      ],
      "caveats": [
        "This flag does not provide backups or prevent every form of workload termination."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "API termination protection is disabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_termination",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_not_older_than_180_days": {
    "description_fields": {
      "description": "Compares LaunchTime with midnight UTC 180 days before the snapshot."
    },
    "remediation_fields": {
      "summary": "Review patch and image-maintenance status before rebuilding an older instance.",
      "steps": [
        "Review patch and image-maintenance status before rebuilding an older instance."
      ],
      "caveats": [
        "Launch age is not an installed-patch or vulnerability assessment."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The instance launch predates the 180-day cutoff.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_age_compliance",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.running_instance_age_180_days": {
    "description_fields": {
      "description": "For running instances, flags whole days since launch greater than 180."
    },
    "remediation_fields": {
      "summary": "Review patch and image-maintenance status before rebuilding older running instances.",
      "steps": [
        "Review patch and image-maintenance status before rebuilding older running instances."
      ],
      "caveats": [
        "Non-running instances are not applicable; age does not prove missing security patches."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The running instance has more than 180 whole days since launch.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_age_prowler",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.stopped_instance_30_days": {
    "description_fields": {
      "description": "For stopped or stopping instances, compares the parsed transition time with the midnight UTC30-day cutoff."
    },
    "remediation_fields": {
      "summary": "Review ownership and recovery purpose before restarting or retiring the stopped instance.",
      "steps": [
        "Review ownership and recovery purpose before restarting or retiring the stopped instance."
      ],
      "caveats": [
        "Other states are not applicable; transition timestamps are parsed from provider metadata."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The instance transition is on or before the 30-day stopped-age cutoff.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_stopped_compliance.<locals>.evaluate",
      "closure": {
        "days": 30
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.stopped_instance_90_days": {
    "description_fields": {
      "description": "For stopped or stopping instances, compares the parsed transition time with the midnight UTC90-day cutoff."
    },
    "remediation_fields": {
      "summary": "Review ownership and recovery purpose before restarting or retiring the stopped instance.",
      "steps": [
        "Review ownership and recovery purpose before restarting or retiring the stopped instance."
      ],
      "caveats": [
        "Other states are not applicable; transition timestamps are parsed from provider metadata."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The instance transition is on or before the 90-day stopped-age cutoff.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_stopped_compliance.<locals>.evaluate",
      "closure": {
        "days": 90
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.stopped_instance_more_than_30_days": {
    "description_fields": {
      "description": "For stopped instances, parses the transition timestamp and flags more than 30 whole days."
    },
    "remediation_fields": {
      "summary": "Review ownership and recovery purpose before restarting or retiring an old stopped instance.",
      "steps": [
        "Review ownership and recovery purpose before restarting or retiring an old stopped instance."
      ],
      "caveats": [
        "Other states are not applicable; unresolved transition timestamps remain undetermined."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The instance has been stopped for more than 30 whole days.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "stopped_prowler",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_ebs_delete_on_termination": {
    "description_fields": {
      "description": "Checks EBS block mappings for DeleteOnTermination=false."
    },
    "remediation_fields": {
      "summary": "Set automatic deletion only for disks whose data should not outlive the instance.",
      "steps": [
        "Set automatic deletion only for disks whose data should not outlive the instance."
      ],
      "caveats": [
        "Intentional persistent volumes can safely use false; disk contents and recovery needs are not assessed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An EBS block-device mapping declares deletion-on-termination disabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_dot",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_single_eni": {
    "description_fields": {
      "description": "Counts declared instance network interfaces and requires exactly one."
    },
    "remediation_fields": {
      "summary": "Retain only the interfaces required by the intended workload or network appliance.",
      "steps": [
        "Retain only the interfaces required by the intended workload or network appliance."
      ],
      "caveats": [
        "Multiple interfaces can be intentional; their count alone does not prove bypass or exposure."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The instance does not declare exactly one network interface.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_enis",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_single_attachable_eni": {
    "description_fields": {
      "description": "Joins attached interfaces and counts efa, interface and trunk types, requiring at most one."
    },
    "remediation_fields": {
      "summary": "Retain the interfaces needed by the intended network design.",
      "steps": [
        "Retain the interfaces needed by the intended network design."
      ],
      "caveats": [
        "Zero interfaces passes this count preference; missing referenced inventory remains undetermined."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "More than one counted attachable network interface is present.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_enis_prowler",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_ssm_managed": {
    "description_fields": {
      "description": "Except stopped instances, joins the instance ID to Systems Manager managed-instance records."
    },
    "remediation_fields": {
      "summary": "Register with Systems Manager if it is the intended management system and grant only required permissions.",
      "steps": [
        "Register with Systems Manager if it is the intended management system and grant only required permissions."
      ],
      "caveats": [
        "Stopped instances are not applicable; registration does not prove online status or patch compliance."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No matching Systems Manager managed-instance record is present.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_ssm",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.active_instance_ssm_managed": {
    "description_fields": {
      "description": "Except pending, terminated and stopped instances, joins the instance ID to Systems Manager records."
    },
    "remediation_fields": {
      "summary": "Register with Systems Manager if it is the intended management system and grant only required permissions.",
      "steps": [
        "Register with Systems Manager if it is the intended management system and grant only required permissions."
      ],
      "caveats": [
        "Excluded states are not applicable; registration is distinct from online health and patch compliance."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No matching Systems Manager managed-instance record is present.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_ssm_prowler",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_ami_not_deprecated": {
    "description_fields": {
      "description": "Joins the instance AMI to visible Amazon-owned images and compares DeprecationTime with the snapshot."
    },
    "remediation_fields": {
      "summary": "Review support and rebuild from an appropriate supported image when needed.",
      "steps": [
        "Review support and rebuild from an appropriate supported image when needed."
      ],
      "caveats": [
        "Non-Amazon or invisible images are not applicable; deprecation is not a direct vulnerability scan."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The instance\u2019s Amazon-owned AMI deprecation time is before the snapshot.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_outdated_ami",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.enclave_host_imdsv2": {
    "description_fields": {
      "description": "For active Nitro Enclave parents, requires HttpTokens=required."
    },
    "remediation_fields": {
      "summary": "Require IMDSv2 on applicable enclave parent instances.",
      "steps": [
        "Require IMDSv2 on applicable enclave parent instances."
      ],
      "caveats": [
        "Non-parent and excluded lifecycle states are not applicable; no metadata request is sent."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The enclave parent does not declare required IMDSv2 tokens.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "enclave_imds",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.enclave_host_running": {
    "description_fields": {
      "description": "For Enclave-enabled instances, flags stopped, shutting-down or terminated state."
    },
    "remediation_fields": {
      "summary": "Review the host\u2019s purpose before restarting it or retiring obsolete attestation dependencies.",
      "steps": [
        "Review the host\u2019s purpose before restarting it or retiring obsolete attestation dependencies."
      ],
      "caveats": [
        "An enabled flag does not prove an enclave workload currently exists."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Enclave-enabled host is stopped, shutting down or terminated.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "enclave_running",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.enclave_host_not_public": {
    "description_fields": {
      "description": "For active enclave parents, inspects public IPv4, global attached IPv6 and subnet Internet-gateway default routes."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Remove unnecessary public addressing or routing from enclave parents after preserving required access.",
      "steps": [
        "Remove unnecessary public addressing or routing from enclave parents after preserving required access."
      ],
      "caveats": [
        "These are separate declared exposure signals, not proof of an end-to-end reachable listener."
      ],
      "cli": [],
      "references": [
        {
          "title": "Amazon EC2 read-only API reference",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Welcome.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The enclave parent has a public address or a declared Internet-gateway default route.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "enclave_public",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.enclave_host_ingress_allowlist": {
    "description_fields": {
      "description": "For enclave parents, flags public-CIDR TCP/UDP ranges extending beyond 22,80 and 443."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary public-source ports to the sources that need them.",
      "steps": [
        "Restrict unnecessary public-source ports to the sources that need them."
      ],
      "caveats": [
        "The source\u2019s fixed allowance includes SSH; required services, routes and listeners are not independently validated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An enclave-parent group permits public-source traffic outside the fixed port allowance.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "enclave_ingress",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.enclave_host_vsock_ports_closed": {
    "description_fields": {
      "description": "For enclave parents, matches public-source TCP rules against 5000,8000\u20138090 and 9000."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Restrict unnecessary public-source access to the matched listener ports.",
      "steps": [
        "Restrict unnecessary public-source access to the matched listener ports."
      ],
      "caveats": [
        "The check matches conventional port numbers; it does not prove a vsock proxy or full network path exists."
      ],
      "cli": [],
      "references": [
        {
          "title": "Amazon EC2 read-only API reference",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Welcome.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An enclave-parent security group permits public-source access to a listed vsock-proxy port.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "enclave_vsock",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_cassandra_not_internet_exposed": {
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 7000, 7001, 7199, 9042, 9160."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 7000, 7001, 7199, 9042, 9160.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "closure": {
        "ports": [
          7000,
          7001,
          7199,
          9042,
          9160
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_cifs_not_internet_exposed": {
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 139, 445."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 139, 445.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "closure": {
        "ports": [
          139,
          445
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_elasticsearch_kibana_not_internet_exposed": {
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 9200, 9300, 5601."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 9200, 9300, 5601.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "closure": {
        "ports": [
          9200,
          9300,
          5601
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_ftp_not_internet_exposed": {
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 20, 21."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 20, 21.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "closure": {
        "ports": [
          20,
          21
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_kafka_not_internet_exposed": {
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 9092."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 9092.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "closure": {
        "ports": [
          9092
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_kerberos_not_internet_exposed": {
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 88, 464, 749, 750."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 88, 464, 749, 750.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "closure": {
        "ports": [
          88,
          464,
          749,
          750
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_ldap_not_internet_exposed": {
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 389, 636."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 389, 636.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "closure": {
        "ports": [
          389,
          636
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_memcached_not_internet_exposed": {
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 11211."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 11211.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "closure": {
        "ports": [
          11211
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_mongodb_not_internet_exposed": {
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 27017, 27018."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 27017, 27018.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "closure": {
        "ports": [
          27017,
          27018
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_mysql_not_internet_exposed": {
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 3306."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 3306.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "closure": {
        "ports": [
          3306
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_oracle_not_internet_exposed": {
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 1521, 2483, 2484."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 1521, 2483, 2484.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "closure": {
        "ports": [
          1521,
          2483,
          2484
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_postgresql_not_internet_exposed": {
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 5432."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 5432.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "closure": {
        "ports": [
          5432
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_rdp_not_internet_exposed": {
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 3389."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 3389.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "closure": {
        "ports": [
          3389
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_redis_not_internet_exposed": {
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 6379."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 6379.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "closure": {
        "ports": [
          6379
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_sqlserver_not_internet_exposed": {
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 1433, 1434."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 1433, 1434.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "closure": {
        "ports": [
          1433,
          1434
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_ssh_not_internet_exposed": {
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 22."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 22.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "closure": {
        "ports": [
          22
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_telnet_not_internet_exposed": {
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 23."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 23.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "closure": {
        "ports": [
          23
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.launch_template_default_imdsv2": {
    "description_fields": {
      "description": "Reads the single marked default launch-template version and requires HttpTokens=required."
    },
    "remediation_fields": {
      "summary": "Create the intended metadata configuration and update the default version after compatibility review.",
      "steps": [
        "Create the intended metadata configuration and update the default version after compatibility review."
      ],
      "caveats": [
        "Inherited settings and a deliberately disabled endpoint do not satisfy this explicit-token preference."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The default launch-template version does not explicitly require IMDSv2 tokens.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ec2_launch_template",
      "predicate_qualname": "lt_default_imds",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.launch_template_default_ebs_encrypted": {
    "description_fields": {
      "description": "In the default template version, checks EBS mappings for Encrypted=true."
    },
    "remediation_fields": {
      "summary": "Declare required EBS encryption while preserving the intended launch behavior.",
      "steps": [
        "Declare required EBS encryption while preserving the intended launch behavior."
      ],
      "caveats": [
        "No mappings is not applicable; regional encryption defaults and referenced snapshots are not resolved."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An EBS mapping in the default template lacks Encrypted=true.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ec2_launch_template",
      "predicate_qualname": "lt_default_ebs",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.launch_template_any_version_imdsv2": {
    "description_fields": {
      "description": "Checks every collected version for required tokens on enabled metadata or an explicitly disabled endpoint."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Review selectable versions and update intended consumers to suitable metadata settings.",
      "steps": [
        "Review selectable versions and update intended consumers to suitable metadata settings."
      ],
      "caveats": [
        "Omitted or unrecognized metadata settings remain undetermined; the source does not resolve inheritance."
      ],
      "cli": [],
      "references": [
        {
          "title": "Amazon EC2 read-only API reference",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Welcome.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "A launch-template version explicitly enables metadata with optional tokens.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "ec2_launch_template",
      "predicate_qualname": "lt_versions_imds",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.launch_template_no_public_ip": {
    "description_fields": {
      "description": "Looks for AssociatePublicIpAddress=true in any template-version network interface."
    },
    "remediation_fields": {
      "summary": "Remove unnecessary automatic public IPv4 assignment from intended launch versions.",
      "steps": [
        "Remove unnecessary automatic public IPv4 assignment from intended launch versions."
      ],
      "caveats": [
        "Existing ENI references remain undetermined; omission does not resolve subnet public-IP defaults."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A template version declares automatic public IPv4 assignment.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ec2_launch_template",
      "predicate_qualname": "lt_public_ip",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.launch_template_instances_no_public_ip": {
    "description_fields": {
      "description": "Joins instances by launch-template ID tag and reads their returned launch interface data."
    },
    "remediation_fields": {
      "summary": "Review unnecessary public-IP assignment in the affected launch configuration and consumers.",
      "steps": [
        "Review unnecessary public-IP assignment in the affected launch configuration and consumers."
      ],
      "caveats": [
        "Templates without tagged instances are not applicable; this is not the instance\u2019s effective address or route."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A tagged instance\u2019s returned launch data enables public IPv4 assignment.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ec2_launch_template",
      "predicate_qualname": "lt_instances_public",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.s3.bucket_public_access_block_all": {
    "batch": "s3-native18",
    "description_fields": {
      "description": "Reads all four bucket-level Block Public Access flags and requires true for each."
    },
    "remediation_fields": {
      "summary": "Enable the intended bucket-level public-access protections without breaking deliberate public content.",
      "steps": [
        "Enable the intended bucket-level public-access protections without breaking deliberate public content."
      ],
      "caveats": [
        "Account-level protection is not combined by this bucket-only baseline; a false flag does not prove public data."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "At least one bucket-level Block Public Access flag is false.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "bucket_all",
      "closure": {}
    }
  },
  "aws.claude_a.s3.prowler_bucket_level_public_access_block": {
    "batch": "s3-native18",
    "description_fields": {
      "description": "Requires IgnorePublicAcls and RestrictPublicBuckets at either bucket or account level."
    },
    "remediation_fields": {
      "summary": "Configure the intended protections at the appropriate bucket or account scope.",
      "steps": [
        "Configure the intended protections at the appropriate bucket or account scope."
      ],
      "caveats": [
        "This checks two protective flags, not actual object access or all four public-block settings."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Neither modeled bucket nor account configuration provides both required public-access flags.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "prowler_bucket_level",
      "closure": {}
    }
  },
  "aws.claude_a.s3.prowler_kms_encryption": {
    "batch": "s3-native18",
    "description_fields": {
      "description": "Reads the first default-encryption rule and accepts aws:kms or aws:kms:dsse."
    },
    "remediation_fields": {
      "summary": "If KMS encryption is required, configure the supported default and review existing objects separately.",
      "steps": [
        "If KMS encryption is required, configure the supported default and review existing objects separately."
      ],
      "caveats": [
        "SSE-S3 is encryption too; the default does not establish existing-object encryption or a customer-managed key."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The first default-encryption rule is absent or does not select SSE-KMS/DSSE-KMS.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "prowler_kms",
      "closure": {}
    }
  },
  "aws.claude_a.s3.replication_rule_enabled": {
    "batch": "s3-native18",
    "description_fields": {
      "description": "Looks for any replication rule with Status=Enabled."
    },
    "remediation_fields": {
      "summary": "Configure replication only where the recovery or distribution design needs it.",
      "steps": [
        "Configure replication only where the recovery or distribution design needs it."
      ],
      "caveats": [
        "The rule destination Region, delivery and recovery outcome are not assessed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No enabled replication rule is declared.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "replication_enabled",
      "closure": {}
    }
  },
  "aws.claude_a.s3.lifecycle_rule_enabled": {
    "batch": "s3-native18",
    "description_fields": {
      "description": "Looks for any lifecycle rule with Status=Enabled."
    },
    "remediation_fields": {
      "summary": "Configure appropriate lifecycle transitions or expiry where needed, preserving required retained data.",
      "steps": [
        "Configure appropriate lifecycle transitions or expiry where needed, preserving required retained data."
      ],
      "caveats": [
        "A missing lifecycle rule is not evidence of public data or failed recovery."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No enabled lifecycle rule is declared.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "lifecycle",
      "closure": {}
    }
  },
  "aws.claude_a.s3.versioning_and_lifecycle": {
    "batch": "s3-native18",
    "description_fields": {
      "description": "For version-enabled buckets, looks for any enabled lifecycle rule."
    },
    "remediation_fields": {
      "summary": "Configure lifecycle management suitable for the retained object versions.",
      "steps": [
        "Configure lifecycle management suitable for the retained object versions."
      ],
      "caveats": [
        "Other versioning states are not applicable; retention adequacy and recovery are separate."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The version-enabled bucket has no enabled lifecycle rule.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "versioning_lifecycle",
      "closure": {}
    }
  },
  "aws.claude_a.s3.object_lock_configured": {
    "batch": "s3-native18",
    "description_fields": {
      "description": "Checks whether an Object Lock configuration is returned."
    },
    "remediation_fields": {
      "summary": "If immutable retention is required, configure supported Object Lock and suitable retention safely.",
      "steps": [
        "If immutable retention is required, configure supported Object Lock and suitable retention safely."
      ],
      "caveats": [
        "Configuration presence does not validate retention periods, legal holds or actual object immutability."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No Object Lock configuration is returned for the bucket.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "object_lock",
      "closure": {}
    }
  },
  "aws.claude_a.s3.event_notifications": {
    "batch": "s3-native18",
    "description_fields": {
      "description": "Looks for nonempty topic, queue or Lambda notification configuration, or a present EventBridge configuration."
    },
    "remediation_fields": {
      "summary": "Configure event notifications only for the integrations that need them.",
      "steps": [
        "Configure event notifications only for the integrations that need them."
      ],
      "caveats": [
        "Configuration presence does not prove event delivery or destination authorization."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No recognized S 3 event-notification configuration is declared.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "notifications",
      "closure": {}
    }
  },
  "aws.claude_a.s3.acls_prohibit_user_access": {
    "batch": "s3-native18",
    "description_fields": {
      "description": "Accepts BucketOwnerEnforced; otherwise compares canonical ACL grantee IDs with the owner ID."
    },
    "remediation_fields": {
      "summary": "Review non-owner ACL grants and migrate intended readers before removing unnecessary grants.",
      "steps": [
        "Review non-owner ACL grants and migrate intended readers before removing unnecessary grants."
      ],
      "caveats": [
        "URI group grants and effective public-access blocking are not evaluated by this particular predicate."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A canonical-user ACL grant identifies a principal other than the bucket owner.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "acl_users",
      "closure": {}
    }
  },
  "aws.claude_a.s3.no_authenticated_users_acl": {
    "batch": "s3-native18",
    "description_fields": {
      "description": "Looks for any bucket ACL grant to the global AuthenticatedUsers group."
    },
    "remediation_fields": {
      "summary": "Remove unnecessary AuthenticatedUsers grants after preserving intended client access.",
      "steps": [
        "Remove unnecessary AuthenticatedUsers grants after preserving intended client access."
      ],
      "caveats": [
        "AuthenticatedUsers spans AWS accounts; Block Public Access and ACL-disablement effects are not evaluated here."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The bucket ACL grants a permission to the global AuthenticatedUsers group.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "no_auth_users",
      "closure": {}
    }
  },
  "aws.claude_a.s3.prowler_acl_disabled": {
    "batch": "s3-native18",
    "description_fields": {
      "description": "Reads the first Object Ownership rule and checks for BucketOwnerEnforced."
    },
    "remediation_fields": {
      "summary": "If ACLs are unnecessary, migrate intended permissions before enabling BucketOwnerEnforced.",
      "steps": [
        "If ACLs are unnecessary, migrate intended permissions before enabling BucketOwnerEnforced."
      ],
      "caveats": [
        "Other ownership models can be intentional; the absence of this setting does not establish public access."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The bucket does not declare BucketOwnerEnforced in its first ownership rule.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "prowler_acl_disabled",
      "closure": {}
    }
  },
  "aws.claude_a.s3.prowler_public_list_acl": {
    "batch": "s3-native18",
    "description_fields": {
      "description": "Looks for AllUsers or AuthenticatedUsers ACL grants of FULL_CONTROL, READ or READ_ACP, unless the modeled bucket/account blocking flags mitigate them."
    },
    "remediation_fields": {
      "summary": "Remove unnecessary public-group ACL grants after preserving intended access.",
      "steps": [
        "Remove unnecessary public-group ACL grants after preserving intended access."
      ],
      "caveats": [
        "READ_ACP concerns ACL visibility, not object reads; WRITE_ACP concerns ACL changes. No object or bucket access is attempted."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A public-group ACL grant matches FULL_CONTROL, READ or READ_ACP without the modeled blocking mitigation.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "_public_case.<locals>.evaluate",
      "closure": {}
    }
  },
  "aws.claude_a.s3.prowler_public_write_acl": {
    "batch": "s3-native18",
    "description_fields": {
      "description": "Looks for AllUsers or AuthenticatedUsers ACL grants of FULL_CONTROL, WRITE or WRITE_ACP, unless the modeled bucket/account blocking flags mitigate them."
    },
    "remediation_fields": {
      "summary": "Remove unnecessary public-group ACL grants after preserving intended access.",
      "steps": [
        "Remove unnecessary public-group ACL grants after preserving intended access."
      ],
      "caveats": [
        "READ_ACP concerns ACL visibility, not object reads; WRITE_ACP concerns ACL changes. No object or bucket access is attempted."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A public-group ACL grant matches FULL_CONTROL, WRITE or WRITE_ACP without the modeled blocking mitigation.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "_public_case.<locals>.evaluate",
      "closure": {}
    }
  },
  "aws.claude_a.s3.policy_no_cross_account_permission_changes": {
    "batch": "s3-native18",
    "description_fields": {
      "description": "Matches external AWS principals with the five exact listed bucket-permission-change actions."
    },
    "remediation_fields": {
      "summary": "Remove or appropriately constrain unnecessary external permission-management grants.",
      "steps": [
        "Remove or appropriately constrain unnecessary external permission-management grants."
      ],
      "caveats": [
        "Action wildcards are not expanded; conditions, resource scope and effective authorization are not resolved."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The policy declares an external principal Allow for a listed bucket-permission-change action.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "cross_account_changes",
      "closure": {}
    }
  },
  "aws.claude_a.s3.perimeter_policy_not_public": {
    "batch": "s3-native18",
    "description_fields": {
      "description": "Applies the bounded perimeter-policy matcher to stored Allow principals and recognized condition forms."
    },
    "remediation_fields": {
      "summary": "Review unnecessary public principals and apply suitable intended account or organization restrictions.",
      "steps": [
        "Review unnecessary public principals and apply suitable intended account or organization restrictions."
      ],
      "caveats": [
        "No policy is not applicable; Block Public Access, denies and effective object access are not established."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The stored policy contains an Allow classified public by the bounded perimeter matcher.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "perimeter_policy",
      "closure": {}
    }
  },
  "aws.claude_a.s3.prowler_cross_account_policy": {
    "batch": "s3-native18",
    "description_fields": {
      "description": "Applies the reviewed public-policy matcher with no trusted external accounts to bucket policy statements."
    },
    "remediation_fields": {
      "summary": "Review external grants and remove or constrain unnecessary access while preserving intended sharing.",
      "steps": [
        "Review external grants and remove or constrain unnecessary access while preserving intended sharing."
      ],
      "caveats": [
        "Trusted-account exceptions are not configured; the result is not independent proof of effective access."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The bucket policy matcher identifies an external or public Allow.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "prowler_cross_account",
      "closure": {}
    }
  },
  "aws.claude_a.s3.prowler_policy_public_write": {
    "batch": "s3-native18",
    "description_fields": {
      "description": "Matches listed public-write policy actions unless bucket or account RestrictPublicBuckets is true."
    },
    "remediation_fields": {
      "summary": "Remove unintended public-write grants or apply suitable protective restrictions.",
      "steps": [
        "Remove unintended public-write grants or apply suitable protective restrictions."
      ],
      "caveats": [
        "No object writes are performed; effective resource scope, denies and application intent require separate review."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The modeled policy permits public write without either RestrictPublicBuckets mitigation.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "prowler_public_write",
      "closure": {}
    }
  },
  "aws.claude_a.s3.access_point_public_access_block": {
    "batch": "s3-native18",
    "description_fields": {
      "description": "Reads all four access-point Block Public Access flags and requires true for each."
    },
    "remediation_fields": {
      "summary": "If stronger blocking is needed, plan a supported access-point replacement without disrupting required clients.",
      "steps": [
        "If stronger blocking is needed, plan a supported access-point replacement without disrupting required clients."
      ],
      "caveats": [
        "A known false flag proves this baseline failure; it does not establish a public bucket or successful access."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "At least one access-point Block Public Access flag is false.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "s3_access_point",
      "predicate_qualname": "access_point",
      "closure": {}
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_management_level_access": {
    "batch": "instance-role17",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed IAM management-level access action."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed IAM management-level access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "closure": {
        "actions": [
          "iam:attachgrouppolicy",
          "iam:attachrolepolicy",
          "iam:attachuserpolicy",
          "iam:createpolicy",
          "iam:createpolicyversion",
          "iam:deleteaccountpasswordpolicy",
          "iam:deletegrouppolicy",
          "iam:deletepolicy",
          "iam:deletepolicyversion",
          "iam:deleterolepermissionsboundary",
          "iam:deleterolepolicy",
          "iam:deleteuserpermissionsboundary",
          "iam:deleteuserpolicy",
          "iam:detachgrouppolicy",
          "iam:detachrolepolicy",
          "iam:detachuserpolicy",
          "iam:putgrouppolicy",
          "iam:putrolepermissionsboundary",
          "iam:putrolepolicy",
          "iam:putuserpermissionsboundary",
          "iam:putuserpolicy",
          "iam:setdefaultpolicyversion",
          "iam:updateassumerolepolicy"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_data_destruction_access": {
    "batch": "instance-role17",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed data destruction access action."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed data destruction access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "closure": {
        "actions": [
          "s3:deletebucket",
          "rds:deletedbcluster",
          "rds:deletedbinstance",
          "rds:deletedbsnapshot",
          "rds:deletedbclustersnapshot",
          "rds:deleteglobalcluster",
          "ec2:deletesnapshot",
          "ec2:deletevolume"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_database_management_write_access": {
    "batch": "instance-role17",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed database management write access action."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed database management write access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "closure": {
        "actions": [
          "rds:modifydbcluster",
          "rds:modifydbclusterendpoint",
          "rds:modifydbinstance",
          "rds:modifydbsnapshot",
          "rds:modifyglobalcluster",
          "dynamodb:updateitem",
          "dynamodb:updatetable",
          "memorydb:updatecluster",
          "neptune-db:resetdatabase",
          "neptune-db:writedataviaquery",
          "docdb-elastic:updatecluster",
          "elasticache:modifycachecluster",
          "cassandra:alter",
          "cassandra:modify",
          "qldb:executestatement",
          "qldb:partiqlupdate",
          "qldb:sendcommand",
          "qldb:updateledger",
          "redshift:modifycluster",
          "redshift:modifyclustersnapshot",
          "redshift:modifyendpointaccess",
          "timestream:updatedatabase",
          "timestream:updatetable",
          "timestream:writerecords"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_privilege_escalation_risk_access": {
    "batch": "instance-role17",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed privilege escalation risk access action."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed privilege escalation risk access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "closure": {
        "actions": [
          "iam:createpolicy",
          "iam:createpolicyversion",
          "iam:setdefaultpolicyversion",
          "iam:passrole",
          "iam:createaccesskey",
          "iam:createloginprofile",
          "iam:updateloginprofile",
          "iam:attachuserpolicy",
          "iam:attachgrouppolicy",
          "iam:attachrolepolicy",
          "iam:putuserpolicy",
          "iam:putgrouppolicy",
          "iam:putrolepolicy",
          "iam:addusertogroup",
          "iam:updateassumerolepolicy"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_new_group_creation_with_attached_policy_access": {
    "batch": "instance-role17",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for the complete listed action combination."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant the complete listed new group creation with attached policy access combination.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "closure": {
        "actions": [
          "iam:creategroup",
          "iam:attachgrouppolicy"
        ],
        "all_of": true
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_new_role_creation_with_attached_policy_access": {
    "batch": "instance-role17",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for the complete listed action combination."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant the complete listed new role creation with attached policy access combination.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "closure": {
        "actions": [
          "iam:createrole",
          "iam:attachrolepolicy"
        ],
        "all_of": true
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_new_user_creation_with_attached_policy_access": {
    "batch": "instance-role17",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for the complete listed action combination."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant the complete listed new user creation with attached policy access combination.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "closure": {
        "actions": [
          "iam:createuser",
          "iam:attachuserpolicy"
        ],
        "all_of": true
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_write_access_to_resource_based_policies": {
    "batch": "instance-role17",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed write access to resource-based policies action."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed write access to resource-based policies action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "closure": {
        "actions": [
          "ecr:setrepositorypolicy",
          "serverlessrepo:putapplicationpolicy",
          "backup:putbackupvaultaccesspolicy",
          "elasticfilesystem:putfilesystempolicy",
          "glacier:setvaultaccesspolicy",
          "secretsmanager:putresourcepolicy",
          "events:putpermission",
          "mediastore:putcontainerpolicy",
          "glue:putresourcepolicy",
          "ses:putidentitypolicy",
          "lambda:addpermission",
          "lambda:addlayerversionpermission",
          "s3:putbucketpolicy",
          "s3:putbucketacl",
          "s3:putobject",
          "s3:putobjectacl",
          "kms:creategrant",
          "kms:putkeypolicy",
          "es:updateelasticsearchdomainconfig",
          "sns:addpermission",
          "sqs:addpermission"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_destruction_kms_access": {
    "batch": "instance-role17",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed KMS decrypt / secret value access action."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed KMS decrypt / secret value access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "closure": {
        "actions": [
          "secretsmanager:getsecretvalue",
          "kms:decrypt"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_destruction_rds_access": {
    "batch": "instance-role17",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed RDS Data API statement execution access action."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed RDS Data API statement execution access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "closure": {
        "actions": [
          "rds-data:executestatement",
          "rds-data:batchexecutestatement"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_cloud_log_tampering_access": {
    "batch": "instance-role17",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed cloud log tampering access action."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed cloud log tampering access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "closure": {
        "actions": [
          "cloudtrail:deletetrail",
          "cloudtrail:puteventselectors",
          "cloudtrail:stoplogging",
          "ec2:deleteflowlogs",
          "s3:putbucketlogging",
          "logs:deletelogstream",
          "logs:deleteloggroup",
          "waf:deleteloggingconfiguration",
          "waf:putloggingconfiguration"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_alter_critical_s3_permissions_configuration": {
    "batch": "instance-role17",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed alter critical S3 permissions configuration action."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed alter critical S 3 permissions configuration action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "closure": {
        "actions": [
          "s3:putobjectretention",
          "s3:putlifecycleconfiguration",
          "s3:putbucketpolicy",
          "s3:putbucketversioning"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_write_permission_on_critical_s3_configuration": {
    "batch": "instance-role17",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed write permission on critical S3 configuration action."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed write permission on critical S 3 configuration action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "closure": {
        "actions": [
          "s3:putobjectretention",
          "s3:putlifecycleconfiguration",
          "s3:putbucketpolicy",
          "s3:putbucketversioning"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_security_group_write_access": {
    "batch": "instance-role17",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed security group write access action."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed security group write access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "closure": {
        "actions": [
          "rds:createdbsecuritygroup",
          "rds:deletedbsecuritygroup",
          "rds:revokedbsecuritygroupingress",
          "ec2:authorizesecuritygroupegress",
          "ec2:authorizesecuritygroupingress",
          "ec2:createsecuritygroup",
          "ec2:deletesecuritygroup",
          "ec2:modifysecuritygrouprules",
          "ec2:revokesecuritygroupegress",
          "ec2:revokesecuritygroupingress",
          "elasticloadbalancing:applysecuritygroupstoloadbalancer",
          "elasticloadbalancing:setsecuritygroups",
          "redshift:authorizeclustersecuritygroupingress",
          "redshift:createclustersecuritygroup",
          "redshift:deleteclustersecuritygroup"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_defense_evasion_impact_of_aws_security_services_access": {
    "batch": "instance-role17",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed defense evasion of AWS security services access action."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed defense evasion of AWS security services access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "closure": {
        "actions": [
          "guardduty:updatedetector",
          "guardduty:deletedetector",
          "guardduty:deletemembers",
          "guardduty:updatefilter",
          "guardduty:deletefilter",
          "shield:disableapplicationlayerautomaticresponse",
          "shield:updateprotectiongroup",
          "shield:deletesubscription",
          "detective:disassociatemembership",
          "detective:deletemembers",
          "inspector:disable",
          "config:stopconfigurationrecorder",
          "config:deleteconfigurationrecorder",
          "config:deleteconfigrule",
          "config:deleteorganizationconfigrule",
          "cloudwatch:disablealarmactions",
          "cloudwatch:disableinsightrules"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_elastic_ip_hijacking_access": {
    "batch": "instance-role17",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed Elastic IP hijacking access action."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed Elastic IP hijacking access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "closure": {
        "actions": [
          "ec2:disassociateaddress",
          "ec2:enableaddresstransfer"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_passrole_and_lambda_invoke_function_access": {
    "batch": "instance-role17",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for the complete listed action combination."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant the complete listed iam:PassRole with Lambda create and invoke function access combination.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "closure": {
        "actions": [
          "iam:passrole",
          "lambda:createfunction",
          "lambda:invokefunction"
        ],
        "all_of": true
      }
    }
  },
  "aws.c2b.lambda.invoke_cloudtrail_logged": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Matches collected CloudTrail selectors containing the function ARN, the Lambda ARN prefix or an advanced Lambda resource-type selector."
    },
    "remediation_fields": {
      "summary": "Configure the intended Lambda data-event selectors and verify actual event delivery.",
      "steps": [
        "Configure the intended Lambda data-event selectors and verify actual event delivery."
      ],
      "caveats": [
        "Trail logging state, other advanced-selector restrictions and delivered Invoke events are not established."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No collected trail selector matches the function under the bounded Lambda selector rules.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_invoke_trail",
      "closure": {}
    }
  },
  "aws.c2b.lambda.url_cors_no_wildcard": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "For function URLs, checks whether CORS AllowOrigins contains the literal wildcard."
    },
    "remediation_fields": {
      "summary": "If every browser origin does not need access, allow only intended web clients.",
      "steps": [
        "If every browser origin does not need access, allow only intended web clients."
      ],
      "caveats": [
        "No URL is not applicable; CORS is a browser policy, not authentication or a network perimeter."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The function URL CORS allowlist contains a wildcard origin.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_cors",
      "closure": {}
    }
  },
  "aws.c2b.lambda.no_cross_account_layers": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Compares each declared layer ARN account with the audited account."
    },
    "remediation_fields": {
      "summary": "Review external layer publishers and retain only the dependencies the workload trusts.",
      "steps": [
        "Review external layer publishers and retain only the dependencies the workload trusts."
      ],
      "caveats": [
        "Cross-account layers can be intentional vendor dependencies; ownership alone does not establish malicious code."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The function references a layer owned by another AWS account.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_layers",
      "closure": {}
    }
  },
  "aws.c2b.lambda.runtime_not_obsolete": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Checks whether the Runtime value belongs to the pinned obsolete-runtime list."
    },
    "remediation_fields": {
      "summary": "Review current runtime support and migrate obsolete runtimes with compatibility testing.",
      "steps": [
        "Review current runtime support and migrate obsolete runtimes with compatibility testing."
      ],
      "caveats": [
        "Functions without Runtime are not applicable; this is not a live current-support or code-vulnerability assessment."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The function runtime belongs to the pinned obsolete-runtime list.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_runtime",
      "closure": {}
    }
  },
  "aws.c2b.ecs.no_credential_named_env_vars": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Checks plain container environment-variable names against the fixed AWS credential-name list."
    },
    "remediation_fields": {
      "summary": "Use a suitable task role or secret-reference mechanism for actual credentials.",
      "steps": [
        "Use a suitable task role or secret-reference mechanism for actual credentials."
      ],
      "caveats": [
        "Values are never read; a name match does not prove that a real secret is present or leaked."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A plain environment variable uses a listed AWS credential-related name.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ecs_task_definition",
      "predicate_qualname": "ecs_env_names",
      "closure": {}
    }
  },
  "aws.c2b.ecs.container_insights": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Looks for any containerInsights setting with value enabled or enhanced."
    },
    "remediation_fields": {
      "summary": "Enable intended Container Insights coverage when this is the chosen monitoring tool.",
      "steps": [
        "Enable intended Container Insights coverage when this is the chosen monitoring tool."
      ],
      "caveats": [
        "Alternative monitoring and telemetry delivery are not assessed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No enabled or enhanced Container Insights setting is declared.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ecs_cluster",
      "predicate_qualname": "ecs_insights",
      "closure": {}
    }
  },
  "aws.c2b.ecs.container_insights_setting": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Requires nonempty containerInsights settings whose values are enabled or enhanced."
    },
    "remediation_fields": {
      "summary": "Configure the intended Container Insights mode where required.",
      "steps": [
        "Configure the intended Container Insights mode where required."
      ],
      "caveats": [
        "Missing source facts remain undetermined; an enabled declaration does not prove telemetry delivery."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Container Insights settings are absent or include a value other than enabled or enhanced.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ecs_cluster",
      "predicate_qualname": "ecs_insights_setting",
      "closure": {}
    }
  },
  "aws.c2b.ecs.cluster_has_active_services": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Reads activeServicesCount and flags zero or fewer."
    },
    "remediation_fields": {
      "summary": "Review whether the cluster intentionally has no services; retire it only after checking other workloads.",
      "steps": [
        "Review whether the cluster intentionally has no services; retire it only after checking other workloads."
      ],
      "caveats": [
        "Standalone tasks can be intentional; no-service count alone is not a security weakness."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The cluster reports no active services.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ecs_cluster",
      "predicate_qualname": "ecs_active",
      "closure": {}
    }
  },
  "aws.c2b.ecs.cluster_has_registered_instances": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Accepts positive registration count; otherwise resolves cluster-matched service and task capacity demand."
    },
    "remediation_fields": {
      "summary": "For proved EC 2 workload demand, investigate missing container-instance registration.",
      "steps": [
        "For proved EC 2 workload demand, investigate missing container-instance registration."
      ],
      "caveats": [
        "Fargate-only workloads are not applicable; unresolved capacity is undetermined and positive registration is not readiness proof."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The cluster has no registered instances despite declared EC 2 workload demand.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ecs_cluster",
      "predicate_qualname": "ecs_registered",
      "closure": {}
    }
  },
  "aws.c2b.ecs.container_instance_agents_connected": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "For clusters with registered instances, checks active matching container-instance agentConnected flags."
    },
    "remediation_fields": {
      "summary": "Restore intended agent connectivity and investigate stale registrations safely.",
      "steps": [
        "Restore intended agent connectivity and investigate stale registrations safely."
      ],
      "caveats": [
        "Zero registered instances is not applicable; this report does not independently test host or agent health."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An active container instance reports its ECS agent disconnected.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ecs_cluster",
      "predicate_qualname": "ecs_agents",
      "closure": {}
    }
  },
  "aws.c2b.eks.endpoint_not_public": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Reads the EKS endpointPublicAccess flag without considering authorized CIDRs."
    },
    "remediation_fields": {
      "summary": "Use a private endpoint if the intended administration model requires it; otherwise review allowed public sources.",
      "steps": [
        "Use a private endpoint if the intended administration model requires it; otherwise review allowed public sources."
      ],
      "caveats": [
        "A CIDR-restricted public endpoint also fails this private-only preference; authentication and effective reachability are not tested."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EKS API endpoint is declared public.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "eks_cluster",
      "predicate_qualname": "eks_public",
      "closure": {}
    }
  },
  "aws.c2b.eks.single_security_group": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Counts additional securityGroupIds and flags more than one."
    },
    "remediation_fields": {
      "summary": "Keep only the additional groups needed by the intended cluster network design.",
      "steps": [
        "Keep only the additional groups needed by the intended cluster network design."
      ],
      "caveats": [
        "Additional groups can be intentional; count does not assess rules or Kubernetes NetworkPolicy."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EKS cluster declares more than one additional security group.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "eks_cluster",
      "predicate_qualname": "eks_sgs",
      "closure": {}
    }
  },
  "aws.c2b.eks.version_at_least_1_19": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Parses the Kubernetes major/minor version and compares it with the pinned 1.19 floor."
    },
    "remediation_fields": {
      "summary": "Review current EKS support and upgrade unsupported workloads through an appropriate plan.",
      "steps": [
        "Review current EKS support and upgrade unsupported workloads through an appropriate plan."
      ],
      "caveats": [
        "Passing this historical floor does not establish current EKS support or complete patch coverage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Kubernetes version is below the pinned 1.19 floor.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "eks_cluster",
      "predicate_qualname": "eks_119",
      "closure": {}
    }
  },
  "aws.c2b.eks.version_at_least_1_28": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Parses the Kubernetes major/minor version and compares it with the pinned 1.28 floor."
    },
    "remediation_fields": {
      "summary": "Review current EKS support and upgrade unsupported workloads through an appropriate plan.",
      "steps": [
        "Review current EKS support and upgrade unsupported workloads through an appropriate plan."
      ],
      "caveats": [
        "Passing this fixed floor does not establish current EKS support or complete patch coverage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Kubernetes version is below the pinned 1.28 floor.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "eks_cluster",
      "predicate_qualname": "eks_128",
      "closure": {}
    }
  },
  "aws.c2b.eks.deletion_protection": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Reads the deletionProtection flag and flags explicit false."
    },
    "remediation_fields": {
      "summary": "Enable deletion protection where accidental cluster deletion must be prevented.",
      "steps": [
        "Enable deletion protection where accidental cluster deletion must be prevented."
      ],
      "caveats": [
        "Missing fields remain undetermined; deletion protection is not a backup or availability guarantee."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "EKS cluster deletion protection is disabled.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "eks_cluster",
      "predicate_qualname": "eks_deletion",
      "closure": {}
    }
  },
  "aws.c2b.eks.secrets_encryption_configured": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Checks whether encryptionConfig contains any entries."
    },
    "remediation_fields": {
      "summary": "If dedicated envelope keys are required, configure an appropriate supported key and preserve access.",
      "steps": [
        "If dedicated envelope keys are required, configure an appropriate supported key and preserve access."
      ],
      "caveats": [
        "The check ignores Kubernetes version and provider-default encryption; absence is not evidence of plaintext secrets."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No explicit EKS encryptionConfig entry is declared.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "eks_cluster",
      "predicate_qualname": "eks_kms",
      "closure": {}
    }
  },
  "aws.c2b.eks.cluster_security_group_present": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Validates the observed cluster security-group ID; missing modern IDs remain undetermined."
    },
    "remediation_fields": {
      "summary": "Inspect the reported cluster group association if its metadata is unresolved.",
      "steps": [
        "Inspect the reported cluster group association if its metadata is unresolved."
      ],
      "caveats": [
        "Legacy pre-boundary groups are not applicable; this presence check has no failing outcome and does not evaluate Kubernetes NetworkPolicy."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The cluster security-group presence is unverified.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "eks_cluster",
      "predicate_qualname": "eks_cluster_sg",
      "closure": {}
    },
    "no_fail_outcome": true
  },
  "aws.c2b.autoscaling.multiple_az": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Counts declared AvailabilityZones and requires at least two."
    },
    "remediation_fields": {
      "summary": "Use multiple Availability Zones where the intended availability requirements need them.",
      "steps": [
        "Use multiple Availability Zones where the intended availability requirements need them."
      ],
      "caveats": [
        "Zone declarations do not establish balanced capacity or actual outage resistance."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Auto Scaling group declares fewer than two Availability Zones.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "autoscaling_group",
      "predicate_qualname": "asg_az",
      "closure": {}
    }
  },
  "aws.c2b.autoscaling.uses_launch_template": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Checks for a nonempty direct or mixed-instances launch-template declaration."
    },
    "remediation_fields": {
      "summary": "Use the intended supported launch-template design when migrating legacy launch configurations.",
      "steps": [
        "Use the intended supported launch-template design when migrating legacy launch configurations."
      ],
      "caveats": [
        "Template presence does not validate version selection or secure launch settings."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No direct or mixed-instances launch-template declaration is present.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "autoscaling_group",
      "predicate_qualname": "asg_lt",
      "closure": {}
    }
  },
  "aws.c2b.autoscaling.capacity_rebalance": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "For groups declaring both classic load balancers and target groups, reads CapacityRebalance."
    },
    "remediation_fields": {
      "summary": "Enable capacity rebalancing if required by the intended Spot-capacity design.",
      "steps": [
        "Enable capacity rebalancing if required by the intended Spot-capacity design."
      ],
      "caveats": [
        "Groups without both balancer types are not applicable under this source criterion; replacement behavior is not tested."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The applicable Auto Scaling group does not enable CapacityRebalance.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "autoscaling_group",
      "predicate_qualname": "asg_rebalance",
      "closure": {}
    }
  },
  "aws.c2b.autoscaling.instance_types_per_az": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Groups current instances by Availability Zone and requires several zones with at least two instance types each."
    },
    "remediation_fields": {
      "summary": "Choose suitable capacity diversification for the intended workload and availability goals.",
      "steps": [
        "Choose suitable capacity diversification for the intended workload and availability goals."
      ],
      "caveats": [
        "Empty instance lists are not applicable; observed diversity is not a guarantee of future capacity."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Current group membership does not provide multiple instance types in every one of several zones.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "autoscaling_group",
      "predicate_qualname": "asg_types",
      "closure": {}
    }
  },
  "aws.c2b.autoscaling.mixed_policy_multiple_types": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Counts distinct explicit InstanceType overrides and requires at least two."
    },
    "remediation_fields": {
      "summary": "Configure appropriate instance-type diversification where required.",
      "steps": [
        "Configure appropriate instance-type diversification where required."
      ],
      "caveats": [
        "Attribute-based selection remains undetermined; this does not evaluate the number of Availability Zones."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The mixed-instances overrides declare fewer than two distinct instance types.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "autoscaling_group",
      "predicate_qualname": "asg_mixed",
      "closure": {}
    }
  },
  "aws.c2b.autoscaling.no_suspended_processes": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Checks whether SuspendedProcesses contains any entries."
    },
    "remediation_fields": {
      "summary": "Review intentional maintenance before resuming required scaling processes.",
      "steps": [
        "Review intentional maintenance before resuming required scaling processes."
      ],
      "caveats": [
        "Suspension can be intentional maintenance; no failed scaling event is demonstrated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "At least one Auto Scaling process is suspended.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "autoscaling_group",
      "predicate_qualname": "asg_suspended",
      "closure": {}
    }
  },
  "aws.c2b.autoscaling.tags_propagate": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Checks declared tags for PropagateAtLaunch=false."
    },
    "remediation_fields": {
      "summary": "Propagate tags where intended for inventory or policy, preserving deliberate exceptions.",
      "steps": [
        "Propagate tags where intended for inventory or policy, preserving deliberate exceptions."
      ],
      "caveats": [
        "No tags passes this preference; tag propagation is not a standalone security boundary."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A group tag is configured not to propagate at launch.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "autoscaling_group",
      "predicate_qualname": "asg_tags",
      "closure": {}
    }
  },
  "aws.c2b.autoscaling.group_lc_imdsv2": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Joins the named launch configuration, requiring tokens unless its metadata endpoint is disabled."
    },
    "remediation_fields": {
      "summary": "Configure required IMDSv2 or disable unnecessary metadata access through the intended launch settings.",
      "steps": [
        "Configure required IMDSv2 or disable unnecessary metadata access through the intended launch settings."
      ],
      "caveats": [
        "Groups without launch configurations are not applicable; unset token inheritance remains undetermined. Launch configurations are immutable: migrate to a pinned reviewed template version and use an instance refresh to replace existing group instances. A group using a launch template is NOT_APPLICABLE to this launch-configuration-specific check."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The group launch configuration does not require IMDSv2 tokens.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "autoscaling_group",
      "predicate_qualname": "asg_lc_imds",
      "closure": {}
    }
  },
  "aws.c2b.autoscaling.lc_imdsv2_required": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Reads launch-configuration metadata HttpTokens and requires required."
    },
    "remediation_fields": {
      "summary": "Use a suitable replacement launch configuration or template with intended IMDSv2 requirements.",
      "steps": [
        "Use a suitable replacement launch configuration or template with intended IMDSv2 requirements."
      ],
      "caveats": [
        "Unset account-default inheritance remains undetermined; a disabled endpoint does not satisfy this explicit-token preference. Launch configurations are immutable: migrate to a pinned reviewed template version and use an instance refresh to replace existing group instances. Moving a group to a launch template does not change this resource finding on the old launch configuration."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The launch configuration explicitly does not require IMDSv2 tokens.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "launch_configuration",
      "predicate_qualname": "lc_imds",
      "closure": {}
    }
  },
  "aws.c2b.autoscaling.lc_hop_limit": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Flags a declared metadata response hop limit greater than one; omission uses the source\u2019s default acceptance."
    },
    "remediation_fields": {
      "summary": "Use a hop limit appropriate for the workload\u2019s container or network-hop requirements.",
      "steps": [
        "Use a hop limit appropriate for the workload\u2019s container or network-hop requirements."
      ],
      "caveats": [
        "Containerized workloads can need a higher hop limit; the value alone does not prove a metadata-exposure path. Launch configurations are immutable: migrate to a pinned reviewed template version and use an instance refresh to replace existing group instances. Moving a group to a launch template does not change this resource finding on the old launch configuration."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The launch configuration metadata response hop limit exceeds one.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "launch_configuration",
      "predicate_qualname": "lc_hop",
      "closure": {}
    }
  },
  "aws.c2b.elasticbeanstalk.stream_logs": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Reads the StreamLogs option in the CloudWatch log configuration namespace and looks for true."
    },
    "remediation_fields": {
      "summary": "Configure intended log streaming and verify the destination receives the required records.",
      "steps": [
        "Configure intended log streaming and verify the destination receives the required records."
      ],
      "caveats": [
        "Unreported options remain undetermined; delivery, retention and alternative logging are separate."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The environment does not declare StreamLogs=true.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "elastic_beanstalk_environment",
      "predicate_qualname": "eb_logs",
      "closure": {}
    }
  },
  "aws.c2b.elasticbeanstalk.managed_updates": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Reads ManagedActionsEnabled in the managed-actions namespace and looks for true."
    },
    "remediation_fields": {
      "summary": "Enable managed updates if they match the intended platform-maintenance process.",
      "steps": [
        "Enable managed updates if they match the intended platform-maintenance process."
      ],
      "caveats": [
        "Configuration does not prove updates installed; a controlled manual process can be intentional."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The environment does not declare managed platform actions enabled.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "elastic_beanstalk_environment",
      "predicate_qualname": "eb_managed",
      "closure": {}
    }
  },
  "aws.c2b.elasticbeanstalk.enhanced_health": {
    "batch": "managed-services30",
    "description_fields": {
      "description": "Reads the health-reporting SystemType option and requires enhanced."
    },
    "remediation_fields": {
      "summary": "Enable enhanced health reporting if it fits the intended monitoring design.",
      "steps": [
        "Enable enhanced health reporting if it fits the intended monitoring design."
      ],
      "caveats": [
        "Reporting mode does not demonstrate application health or an absence of other monitoring."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The environment does not declare enhanced health reporting.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "elastic_beanstalk_environment",
      "predicate_qualname": "eb_health",
      "closure": {}
    }
  },
  "aws.b.fsx.openzfs_multi_az": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "For OPENZFS filesystems, compares OpenZFSConfiguration.DeploymentType with MULTI_AZ_1."
    },
    "remediation_fields": {
      "summary": "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement.",
      "steps": [
        "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement."
      ],
      "caveats": [
        "Other filesystem types are not applicable; this declaration does not test failover or a current outage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The OPENZFS deployment type is outside the source-selected Multi-AZ values.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "_deployment.<locals>.evaluate",
      "closure": {
        "configuration": "OpenZFSConfiguration",
        "eligible": "OPENZFS",
        "passing": [
          "MULTI_AZ_1"
        ]
      }
    }
  },
  "aws.b.fsx.netapp_ontap_multi_az": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "For ONTAP filesystems, compares OntapConfiguration.DeploymentType with MULTI_AZ_1, MULTI_AZ_2."
    },
    "remediation_fields": {
      "summary": "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement.",
      "steps": [
        "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement."
      ],
      "caveats": [
        "Other filesystem types are not applicable; this declaration does not test failover or a current outage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The ONTAP deployment type is outside the source-selected Multi-AZ values.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "_deployment.<locals>.evaluate",
      "closure": {
        "configuration": "OntapConfiguration",
        "eligible": "ONTAP",
        "passing": [
          "MULTI_AZ_1",
          "MULTI_AZ_2"
        ]
      }
    }
  },
  "aws.b.fsx.windows_multi_az": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "For WINDOWS filesystems, compares WindowsConfiguration.DeploymentType with MULTI_AZ_1."
    },
    "remediation_fields": {
      "summary": "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement.",
      "steps": [
        "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement."
      ],
      "caveats": [
        "Other filesystem types are not applicable; this declaration does not test failover or a current outage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The WINDOWS deployment type is outside the source-selected Multi-AZ values.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "_deployment.<locals>.evaluate",
      "closure": {
        "configuration": "WindowsConfiguration",
        "eligible": "WINDOWS",
        "passing": [
          "MULTI_AZ_1"
        ]
      }
    }
  },
  "aws.b.fsx.openzfs_copy_backup_and_volume_tags": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "For OpenZFS, reads CopyTagsToBackups and CopyTagsToVolumes and requires enabled."
    },
    "remediation_fields": {
      "summary": "Propagate intended ownership and classification tags to backups and volumes where needed.",
      "steps": [
        "Propagate intended ownership and classification tags to backups and volumes where needed."
      ],
      "caveats": [
        "Other filesystem types are not applicable; tag copying does not demonstrate backup completeness or data protection."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Tag copying to the required backups and volumes is not fully enabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "zfs_tags",
      "closure": {}
    }
  },
  "aws.b.fsx.lustre_copy_backup_tags": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "For Lustre, reads CopyTagsToBackups and requires enabled."
    },
    "remediation_fields": {
      "summary": "Propagate intended ownership and classification tags to backups where needed.",
      "steps": [
        "Propagate intended ownership and classification tags to backups where needed."
      ],
      "caveats": [
        "Other filesystem types are not applicable; tag copying does not demonstrate backup completeness or data protection."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Tag copying to the required backups is not fully enabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "lustre_tags",
      "closure": {}
    }
  },
  "aws.cb.fsx.copy_tags_to_backups": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "For supported FSx types, reads CopyTagsToBackups and requires enabled."
    },
    "remediation_fields": {
      "summary": "Propagate intended ownership and classification tags to backups where needed.",
      "steps": [
        "Propagate intended ownership and classification tags to backups where needed."
      ],
      "caveats": [
        "Other filesystem types are not applicable; tag copying does not demonstrate backup completeness or data protection."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Tag copying to the required backups is not fully enabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "fsx_copy_backups",
      "closure": {}
    }
  },
  "aws.cb.fsx.copy_tags_to_volumes": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "For OpenZFS, reads CopyTagsToVolumes and requires enabled."
    },
    "remediation_fields": {
      "summary": "Propagate intended ownership and classification tags to volumes where needed.",
      "steps": [
        "Propagate intended ownership and classification tags to volumes where needed."
      ],
      "caveats": [
        "Other filesystem types are not applicable; tag copying does not demonstrate backup completeness or data protection."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Tag copying to the required volumes is not fully enabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "fsx_copy_volumes",
      "closure": {}
    }
  },
  "aws.cb.fsx.openzfs_copy_tags_backups_and_volumes": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "For OpenZFS, reads CopyTagsToBackups and CopyTagsToVolumes and requires enabled."
    },
    "remediation_fields": {
      "summary": "Propagate intended ownership and classification tags to backups and volumes where needed.",
      "steps": [
        "Propagate intended ownership and classification tags to backups and volumes where needed."
      ],
      "caveats": [
        "Other filesystem types are not applicable; tag copying does not demonstrate backup completeness or data protection."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Tag copying to the required backups and volumes is not fully enabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "fsx_openzfs_both",
      "closure": {}
    }
  },
  "aws.cb.fsx.lustre_copy_tags_to_backups": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "For Lustre, reads CopyTagsToBackups and requires enabled."
    },
    "remediation_fields": {
      "summary": "Propagate intended ownership and classification tags to backups where needed.",
      "steps": [
        "Propagate intended ownership and classification tags to backups where needed."
      ],
      "caveats": [
        "Other filesystem types are not applicable; tag copying does not demonstrate backup completeness or data protection."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Tag copying to the required backups is not fully enabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "fsx_lustre_tags",
      "closure": {}
    }
  },
  "aws.cb.fsx.ontap_multi_az": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "For ONTAP filesystems, compares OntapConfiguration.DeploymentType with MULTI_AZ_1, MULTI_AZ_2."
    },
    "remediation_fields": {
      "summary": "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement.",
      "steps": [
        "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement."
      ],
      "caveats": [
        "Other filesystem types are not applicable; this declaration does not test failover or a current outage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The ONTAP deployment type is outside the source-selected Multi-AZ values.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "_multi.<locals>.evaluate",
      "closure": {
        "allowed": [
          "MULTI_AZ_1",
          "MULTI_AZ_2"
        ],
        "config": "OntapConfiguration",
        "fstype": "ONTAP"
      }
    }
  },
  "aws.cb.fsx.openzfs_multi_az": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "For OPENZFS filesystems, compares OpenZFSConfiguration.DeploymentType with MULTI_AZ_1."
    },
    "remediation_fields": {
      "summary": "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement.",
      "steps": [
        "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement."
      ],
      "caveats": [
        "Other filesystem types are not applicable; this declaration does not test failover or a current outage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The OPENZFS deployment type is outside the source-selected Multi-AZ values.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "_multi.<locals>.evaluate",
      "closure": {
        "allowed": [
          "MULTI_AZ_1"
        ],
        "config": "OpenZFSConfiguration",
        "fstype": "OPENZFS"
      }
    }
  },
  "aws.cb.fsx.windows_multi_az_deployment": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "For WINDOWS filesystems, compares WindowsConfiguration.DeploymentType with MULTI_AZ_1."
    },
    "remediation_fields": {
      "summary": "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement.",
      "steps": [
        "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement."
      ],
      "caveats": [
        "Other filesystem types are not applicable; this declaration does not test failover or a current outage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The WINDOWS deployment type is outside the source-selected Multi-AZ values.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "_multi.<locals>.evaluate",
      "closure": {
        "allowed": [
          "MULTI_AZ_1"
        ],
        "config": "WindowsConfiguration",
        "fstype": "WINDOWS"
      }
    }
  },
  "aws.cb.fsx.windows_multiple_subnets": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "For FSx Windows filesystems, counts SubnetIds and requires more than one."
    },
    "remediation_fields": {
      "summary": "Use the appropriate supported multi-subnet design if the workload needs it.",
      "steps": [
        "Use the appropriate supported multi-subnet design if the workload needs it."
      ],
      "caveats": [
        "Other filesystem types are not applicable; subnet count alone does not prove separate Availability Zones."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Windows filesystem declares at most one subnet.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "fsx_windows_subnets",
      "closure": {}
    }
  },
  "aws.cb.fsx.protected_by_backup_plan": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "Matches the filesystem ResourceARN to FSx entries in AWS Backup protected resources."
    },
    "remediation_fields": {
      "summary": "Configure required backup protection and verify suitable recovery points.",
      "steps": [
        "Configure required backup protection and verify suitable recovery points."
      ],
      "caveats": [
        "Alternative backup mechanisms and successful restores are not assessed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The FSx filesystem has no matching AWS Backup protected-resource record.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "fsx_backup",
      "closure": {}
    }
  },
  "aws.c2b.efs.file_system_protected_resource": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "Matches the EFS filesystem ARN to EFS entries in AWS Backup protected resources."
    },
    "remediation_fields": {
      "summary": "Configure required backup protection and verify suitable recovery points.",
      "steps": [
        "Configure required backup protection and verify suitable recovery points."
      ],
      "caveats": [
        "This inventories protected resources, not every backup selection or actual restore outcome."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EFS filesystem has no matching AWS Backup protected-resource record.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "efs_protected",
      "closure": {}
    }
  },
  "aws.c2b.efs.backup_not_disabled": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "Reads EFS BackupPolicy.Status and flags DISABLED, DISABLING or confirmed policy absence."
    },
    "remediation_fields": {
      "summary": "Enable intended automatic backups if this is the required backup mechanism.",
      "steps": [
        "Enable intended automatic backups if this is the required backup mechanism."
      ],
      "caveats": [
        "ENABLING passes this transition criterion; unrecognized values remain undetermined and completed backups are not proven."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EFS automatic-backup policy is disabled, disabling or confirmed absent.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "efs_backup_prowler",
      "closure": {}
    }
  },
  "aws.c2b.efs.automatic_backups_enabled": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "Reads EFS BackupPolicy.Status and requires exactly ENABLED."
    },
    "remediation_fields": {
      "summary": "Enable required automatic backups and verify they reach the intended active state.",
      "steps": [
        "Enable required automatic backups and verify they reach the intended active state."
      ],
      "caveats": [
        "ENABLING fails this stricter state preference; unknown values remain undetermined and actual recovery is not tested."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EFS automatic-backup policy is absent or not in ENABLED state.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "efs_backup_turbot",
      "closure": {}
    }
  },
  "aws.c2b.efs.policy_no_wildcard_allow": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "Looks for stored EFS policy Allow statements with a wildcard principal."
    },
    "remediation_fields": {
      "summary": "Review broad principals and retain only the sharing required by the workload.",
      "steps": [
        "Review broad principals and retain only the sharing required by the workload."
      ],
      "caveats": [
        "Conditions are ignored by this exact check; no policy passes, and routing or effective client authorization is not established."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The stored EFS policy contains a wildcard-principal Allow.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "efs_wildcard",
      "closure": {}
    }
  },
  "aws.c2b.efs.policy_prohibit_public_access": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "Applies the bounded perimeter matcher to stored EFS Allow statements and recognized restrictions."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary public principals using suitable workload-specific restrictions.",
      "steps": [
        "Narrow unnecessary public principals using suitable workload-specific restrictions."
      ],
      "caveats": [
        "No policy is not applicable; this is not proof of Internet reachability, successful mounts or actual file access."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The stored EFS policy matcher identifies a public Allow statement.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "efs_public_x",
      "closure": {}
    }
  },
  "aws.c2b.efs.multi_az_mount_targets": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "Flags a declared One Zone identifier or, otherwise, one or fewer mount targets."
    },
    "remediation_fields": {
      "summary": "Use the appropriate supported regional storage and mount-target design where availability requires it.",
      "steps": [
        "Use the appropriate supported regional storage and mount-target design where availability requires it."
      ],
      "caveats": [
        "Mount-target count is not an independent proof of Availability Zone distribution or recovery readiness. A One Zone filesystem cannot accept another mount target in a different Availability Zone; use a Regional filesystem migration if that availability design is required."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The filesystem is One Zone or reports at most one mount target.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "efs_multi_az",
      "closure": {}
    }
  },
  "aws.c2b.efs.access_points_no_root_directory": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "Joins filesystem access points and flags RootDirectory.Path equal to /."
    },
    "remediation_fields": {
      "summary": "If a narrower directory boundary is required, migrate consumers to an appropriately scoped access point.",
      "steps": [
        "If a narrower directory boundary is required, migrate consumers to an appropriately scoped access point."
      ],
      "caveats": [
        "No access points is not applicable; root-directory scope does not bypass POSIX or IAM authorization."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A filesystem access point declares the filesystem root as its root directory.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "efs_aps_root",
      "closure": {}
    }
  },
  "aws.c2b.efs.access_points_posix_user": {
    "batch": "filesystem22",
    "description_fields": {
      "description": "Joins filesystem access points and checks for a nonempty PosixUser declaration."
    },
    "remediation_fields": {
      "summary": "Use an enforced suitable POSIX identity where the intended access-point design requires it.",
      "steps": [
        "Use an enforced suitable POSIX identity where the intended access-point design requires it."
      ],
      "caveats": [
        "No access points is not applicable; presence does not validate UID/GID values or effective file permissions."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An access point does not declare a nonempty POSIX user configuration.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "efs_aps_user",
      "closure": {}
    }
  },
  "aws.ec2.imdsv2": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Reads MetadataOptions and requires HttpTokens=required when HttpEndpoint is enabled."
    },
    "remediation_fields": {
      "summary": "Require IMDSv2 tokens or disable the metadata endpoint if unused.",
      "steps": [
        "Require IMDSv2 tokens or disable the metadata endpoint if unused."
      ],
      "caveats": [
        "Disabled metadata passes; unknown endpoint or token states remain undetermined."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The enabled instance metadata endpoint allows IMDSv 1 requests.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "aws_imds",
      "closure": {}
    }
  },
  "aws.s3.versioning": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Reads Versioning.Status and requires Enabled."
    },
    "remediation_fields": {
      "summary": "Enable versioning where object recovery requires it and set suitable retention.",
      "steps": [
        "Enable versioning where object recovery requires it and set suitable retention."
      ],
      "caveats": [
        "Versioning alone does not prove recovery readiness or prevent permanent deletion."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Bucket versioning is suspended or not enabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "versioning",
      "closure": {}
    }
  },
  "aws.s3.access_logging": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Checks whether Logging.LoggingEnabled declares a target bucket."
    },
    "remediation_fields": {
      "summary": "Configure server access logging when needed, or assess the intended alternative audit mechanism.",
      "steps": [
        "Configure server access logging when needed, or assess the intended alternative audit mechanism."
      ],
      "caveats": [
        "CloudTrail coverage and successful log delivery are separate checks."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The bucket has no server access logging configuration.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "logging",
      "closure": {}
    }
  },
  "aws.eks.control_plane_logging": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Collects enabled clusterLogging types and requires api, audit, authenticator, controllerManager and scheduler."
    },
    "remediation_fields": {
      "summary": "Enable the missing control-plane log categories needed for investigation.",
      "steps": [
        "Enable the missing control-plane log categories needed for investigation."
      ],
      "caveats": [
        "This checks enabled category declarations, not delivery, retention or log completeness."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "One or more EKS control-plane log categories are disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "eks_cluster",
      "predicate_qualname": "eks_logging",
      "closure": {}
    }
  },
  "aws.lambda.vpc_configuration": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Reads VpcConfig.VpcId and requires a nonempty VPC identifier."
    },
    "remediation_fields": {
      "summary": "Attach the function to a VPC if it needs private resources or controlled network egress.",
      "steps": [
        "Attach the function to a VPC if it needs private resources or controlled network egress."
      ],
      "caveats": [
        "A VPC is not required for every function; this does not prove exposure or deficient isolation."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Lambda function does not declare a VPC attachment.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "nonempty.<locals>.evaluate",
      "closure": {
        "path": "VpcConfig.VpcId"
      }
    }
  },
  "aws.lambda.dead_letter_queue": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Checks for a nonempty DeadLetterConfig.TargetArn declaration."
    },
    "remediation_fields": {
      "summary": "Configure an appropriate failure destination if the function invocation model needs it.",
      "steps": [
        "Configure an appropriate failure destination if the function invocation model needs it."
      ],
      "caveats": [
        "This does not assess asynchronous destinations, queue permissions or successful message delivery."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The function does not declare a dead-letter target.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_dlq",
      "closure": {}
    }
  },
  "aws.lambda.function_url_authentication": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "For an existing function URL, compares AuthType with AWS_IAM."
    },
    "remediation_fields": {
      "summary": "Use IAM authentication or verify that anonymous access is intentional and appropriately constrained.",
      "steps": [
        "Use IAM authentication or verify that anonymous access is intentional and appropriately constrained."
      ],
      "caveats": [
        "No URL is not applicable; invocation policy and actual network reachability remain separate."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Lambda function URL allows unauthenticated requests.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_url",
      "closure": {}
    }
  },
  "aws.b.ecs.no_privileged_containers": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Checks every container privileged flag, treating an omitted flag as false."
    },
    "remediation_fields": {
      "summary": "Remove privileged mode from containers that do not require host-level capabilities.",
      "steps": [
        "Remove privileged mode from containers that do not require host-level capabilities."
      ],
      "caveats": [
        "Malformed flags remain undetermined unless another container proves a failure."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "At least one ECS container requests privileged mode.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "ecs_task_definition",
      "predicate_qualname": "privileges",
      "closure": {}
    }
  },
  "aws.b.ecs.some_logging_configuration": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Checks whether at least one container declares a non-null logConfiguration object."
    },
    "remediation_fields": {
      "summary": "Configure suitable logging for the containers whose activity must be recorded.",
      "steps": [
        "Configure suitable logging for the containers whose activity must be recorded."
      ],
      "caveats": [
        "An empty object satisfies this presence check; sibling coverage, valid drivers and actual delivery are not assessed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No ECS container declares a logging configuration.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ecs_task_definition",
      "predicate_qualname": "logging",
      "closure": {}
    }
  },
  "aws.b.ecs.no_host_pid": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Reads task pidMode and flags host."
    },
    "remediation_fields": {
      "summary": "Use a scoped PID namespace unless host-process visibility is required.",
      "steps": [
        "Use a scoped PID namespace unless host-process visibility is required."
      ],
      "caveats": [
        "This is a namespace declaration; it does not establish actual host process access."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The ECS task uses the host PID namespace.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ecs_task_definition",
      "predicate_qualname": "host_pid",
      "closure": {}
    }
  },
  "aws.b.ecs.all_readonly_roots": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Requires readonlyRootFilesystem=true for every declared container."
    },
    "remediation_fields": {
      "summary": "Make container root filesystems read-only where supported and place required writes on dedicated volumes.",
      "steps": [
        "Make container root filesystems read-only where supported and place required writes on dedicated volumes."
      ],
      "caveats": [
        "This checks task declarations, not actual write activity or every mounted volume."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "At least one ECS container has a writable root filesystem.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ecs_task_definition",
      "predicate_qualname": "readonly_roots",
      "closure": {}
    }
  },
  "aws.b.ecs.declared_nonroot_users": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "For proven Linux tasks, requires each container to declare a valid nonzero numeric UID."
    },
    "remediation_fields": {
      "summary": "Declare a suitable non-root numeric UID and verify that application file permissions support it.",
      "steps": [
        "Declare a suitable non-root numeric UID and verify that application file permissions support it."
      ],
      "caveats": [
        "Inherited image users, named users and malformed values remain undetermined; runtime process identity is not measured."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "At least one Linux ECS container explicitly declares the root user.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "ecs_task_definition",
      "predicate_qualname": "nonroot_users",
      "closure": {}
    }
  },
  "aws.b.ecs.host_network_nonprivileged": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "For host-network Linux tasks, combines container privilege flags with valid non-root numeric UID declarations."
    },
    "remediation_fields": {
      "summary": "Remove unnecessary host-network privileges and configure suitable non-root container users.",
      "steps": [
        "Remove unnecessary host-network privileges and configure suitable non-root container users."
      ],
      "caveats": [
        "Other network modes are not applicable; unresolved user identities remain undetermined unless another failure is proven."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A host-network Linux ECS container requests privilege or explicitly declares root.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "ecs_task_definition",
      "predicate_qualname": "host_user",
      "closure": {}
    }
  },
  "aws.cb.lambda.kms_key_configured": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Checks whether the function declares a nonempty KMSKeyArn."
    },
    "remediation_fields": {
      "summary": "Configure a customer-managed key if independent key control is required.",
      "steps": [
        "Configure a customer-managed key if independent key control is required."
      ],
      "caveats": [
        "The AWS-managed default may still encrypt environment variables; absence is not proof of plaintext storage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The function does not declare a customer-managed environment-encryption key.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_kms",
      "closure": {}
    }
  },
  "aws.cb.lambda.logging_config_present": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Checks that the collected LoggingConfig member is not null."
    },
    "remediation_fields": {
      "summary": "Configure suitable function log format, levels and destination when required.",
      "steps": [
        "Configure suitable function log format, levels and destination when required."
      ],
      "caveats": [
        "An empty object passes this presence criterion; an unread member remains undetermined and delivery is not tested."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The function returns an explicit null logging configuration.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_logging",
      "closure": {}
    }
  },
  "aws.cb.lambda.vpc_multiple_az": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Joins VPC subnet identifiers to inventory and requires two distinct AvailabilityZoneId values."
    },
    "remediation_fields": {
      "summary": "Use subnets in multiple Availability Zones if the function availability requirements need it.",
      "steps": [
        "Use subnets in multiple Availability Zones if the function availability requirements need it."
      ],
      "caveats": [
        "Non-VPC functions are not applicable; missing referenced subnets remain undetermined."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The VPC-attached function spans fewer than two known Availability Zones.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_azs",
      "closure": {}
    }
  },
  "aws.cb.lambda.policy_no_wildcard_allow": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Finds wildcard-principal Allow statements in the stored function policy, ignoring conditions."
    },
    "remediation_fields": {
      "summary": "Review wildcard principals and retain only intended invocation access.",
      "steps": [
        "Review wildcard principals and retain only intended invocation access."
      ],
      "caveats": [
        "Conditions are ignored by this criterion; no policy passes and successful invocation is not demonstrated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The function policy contains a wildcard-principal Allow statement.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_public_c",
      "closure": {}
    }
  },
  "aws.cb.lambda.policy_prohibit_public_access_perimeter": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Applies the bounded public-principal matcher and recognized restrictions to stored policy Allow statements."
    },
    "remediation_fields": {
      "summary": "Narrow unnecessary public principals or apply suitable supported restrictions.",
      "steps": [
        "Narrow unnecessary public principals or apply suitable supported restrictions."
      ],
      "caveats": [
        "No policy is not applicable; this does not probe invocation or prove complete effective permissions."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The stored function policy matcher identifies a public Allow statement.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_public_x",
      "closure": {}
    }
  },
  "aws.cb.lambda.runtime_not_deprecated_list": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Compares managed Zip runtime deprecation dates with the captured scan date using the reviewed lifecycle snapshot."
    },
    "remediation_fields": {
      "summary": "Move the function to a supported runtime and validate application compatibility.",
      "steps": [
        "Move the function to a supported runtime and validate application compatibility."
      ],
      "caveats": [
        "Image and custom runtimes are not applicable; unlisted runtimes or expired lifecycle snapshots remain undetermined."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The managed Lambda runtime is deprecated at the captured scan date.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_runtime",
      "closure": {}
    }
  },
  "aws.cb.lambda.cloudtrail_data_events": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Requires an actively logging, region-covering trail with a Lambda Invoke selector matching this function ARN."
    },
    "remediation_fields": {
      "summary": "Add appropriate Lambda invocation data-event coverage to an active trail.",
      "steps": [
        "Add appropriate Lambda invocation data-event coverage to an active trail."
      ],
      "caveats": [
        "Unresolved trail status or selectors remain undetermined; delivery and retention are not tested."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No verified active trail covers this function invocation data events.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_trail",
      "closure": {}
    }
  },
  "aws.cb.lightsail.instance_auto_snapshot": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Checks for an AutoSnapshot add-on with status Enabled."
    },
    "remediation_fields": {
      "summary": "Enable automatic snapshots where this is the intended backup mechanism.",
      "steps": [
        "Enable automatic snapshots where this is the intended backup mechanism."
      ],
      "caveats": [
        "This does not inspect alternative backups, recovery-point completeness or successful restores."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Lightsail instance has no enabled automatic-snapshot add-on.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lightsail_instance",
      "predicate_qualname": "ls_snap",
      "closure": {}
    }
  },
  "aws.cb.lightsail.instance_ipv6_disabled": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Checks whether the instance declares any IPv6 addresses."
    },
    "remediation_fields": {
      "summary": "Keep IPv6 only where required and restrict the intended IPv6 listeners appropriately.",
      "steps": [
        "Keep IPv6 only where required and restrict the intended IPv6 listeners appropriately."
      ],
      "caveats": [
        "An IPv6 address alone does not prove an open listener or public network path."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Lightsail instance declares IPv6 addresses.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lightsail_instance",
      "predicate_qualname": "ls_ipv6",
      "closure": {}
    }
  },
  "aws.cb.lightsail.instance_not_public": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Requires both a public IP and a declared port range with accessType=public to flag the instance."
    },
    "remediation_fields": {
      "summary": "Review the public listeners and restrict only access that the workload does not need.",
      "steps": [
        "Review the public listeners and restrict only access that the workload does not need."
      ],
      "caveats": [
        "This checks declared port classifications, not packet reachability or application authentication."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Lightsail instance has a public IP and a publicly classified port range.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lightsail_instance",
      "predicate_qualname": "ls_public",
      "closure": {}
    }
  },
  "aws.cb.lightsail.ssh_rdp_http_world_closed": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Checks whether bounded TCP port intervals include 22, 80, 3389 and allow IPv4 or IPv6 world sources.",
      "pass_when": "No valid TCP interval containing 22, 80 or 3389 permits 0.0.0.0/0 or ::/0.",
      "fail_when": "A valid TCP interval containing 22, 80 or 3389 permits 0.0.0.0/0 or ::/0."
    },
    "remediation_fields": {
      "summary": "Restrict administrative access to necessary sources; retain public HTTP only if the workload needs it.",
      "steps": [
        "Restrict administrative access to necessary sources; retain public HTTP only if the workload needs it."
      ],
      "caveats": [
        "Malformed intervals remain undetermined; these rule declarations do not prove a complete reachable network path."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Lightsail TCP rules allow worldwide access to a checked port.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "lightsail_instance",
      "predicate_qualname": "ls_world",
      "closure": {},
      "helper_contract": {
        "qualname": "_open_ports"
      }
    },
    "criterion_correction": "Inclusive bounded TCP intervals are tested for containing the selected port; exact interval endpoints no longer required."
  },
  "aws.cb.lightsail.ssh_restricted": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Checks whether bounded TCP port intervals include 22 and allow the IPv4 world source.",
      "pass_when": "No valid TCP interval containing 22 permits 0.0.0.0/0.",
      "fail_when": "A valid TCP interval containing 22 permits 0.0.0.0/0."
    },
    "remediation_fields": {
      "summary": "Restrict administrative access to necessary sources; retain public HTTP only if the workload needs it.",
      "steps": [
        "Restrict administrative access to necessary sources; retain public HTTP only if the workload needs it."
      ],
      "caveats": [
        "Malformed intervals remain undetermined; these rule declarations do not prove a complete reachable network path."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Lightsail TCP rules allow worldwide access to a checked port.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "lightsail_instance",
      "predicate_qualname": "_ls_port.<locals>.evaluate",
      "closure": {
        "port": 22
      },
      "helper_contract": {
        "qualname": "_open_ports"
      }
    },
    "criterion_correction": "Inclusive bounded TCP intervals are tested for containing the selected port; exact interval endpoints no longer required."
  },
  "aws.cb.lightsail.rdp_restricted": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Checks whether bounded TCP port intervals include 3389 and allow the IPv4 world source.",
      "pass_when": "No valid TCP interval containing 3389 permits 0.0.0.0/0.",
      "fail_when": "A valid TCP interval containing 3389 permits 0.0.0.0/0."
    },
    "remediation_fields": {
      "summary": "Restrict administrative access to necessary sources; retain public HTTP only if the workload needs it.",
      "steps": [
        "Restrict administrative access to necessary sources; retain public HTTP only if the workload needs it."
      ],
      "caveats": [
        "Malformed intervals remain undetermined; these rule declarations do not prove a complete reachable network path."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Lightsail TCP rules allow worldwide access to a checked port.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "lightsail_instance",
      "predicate_qualname": "_ls_port.<locals>.evaluate",
      "closure": {
        "port": 3389
      },
      "helper_contract": {
        "qualname": "_open_ports"
      }
    },
    "criterion_correction": "Inclusive bounded TCP intervals are tested for containing the selected port; exact interval endpoints no longer required."
  },
  "aws.c2b.emr.cluster_kerberos_enabled": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Checks whether collected cluster details include a non-null KerberosAttributes object."
    },
    "remediation_fields": {
      "summary": "Configure Kerberos when the cluster authentication model requires it.",
      "steps": [
        "Configure Kerberos when the cluster authentication model requires it."
      ],
      "caveats": [
        "An empty object passes this presence criterion; actual authentication behavior is not tested."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EMR cluster does not declare Kerberos attributes.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "emr_cluster",
      "predicate_qualname": "emr_kerberos",
      "closure": {}
    }
  },
  "aws.c2b.emr.cluster_security_configuration": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Checks for a nonempty SecurityConfiguration name in collected cluster details."
    },
    "remediation_fields": {
      "summary": "Attach an appropriate EMR security configuration if required by the workload.",
      "steps": [
        "Attach an appropriate EMR security configuration if required by the workload."
      ],
      "caveats": [
        "The named configuration contents and effective encryption or authentication are not assessed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EMR cluster does not declare a security-configuration name.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "emr_cluster",
      "predicate_qualname": "emr_secconf",
      "closure": {}
    }
  },
  "aws.a.s3.mfa_delete_enabled": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Reads collected Versioning.MFADelete and requires Enabled."
    },
    "remediation_fields": {
      "summary": "Consider MFA Delete where its operational restrictions fit the intended deletion-protection design.",
      "steps": [
        "Consider MFA Delete where its operational restrictions fit the intended deletion-protection design."
      ],
      "caveats": [
        "Unproven absence remains undetermined; versioning, Object Lock and effective deletion permissions are separate."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "S 3 MFA Delete is disabled or confirmed absent.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "mfa_delete",
      "closure": {}
    }
  },
  "aws.a.s3.bucket_account_public_blocks": {
    "batch": "containers-serverless30",
    "description_fields": {
      "description": "Requires every Public Access Block setting at bucket scope or the verified owning-account scope."
    },
    "remediation_fields": {
      "summary": "Enable the missing preventive block settings unless intended public distribution requires a reviewed exception.",
      "steps": [
        "Enable the missing preventive block settings unless intended public distribution requires a reviewed exception."
      ],
      "caveats": [
        "These preventive declarations do not establish that any object is currently public."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "One or more effective S 3 Public Access Block settings are disabled.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "public_blocks",
      "closure": {}
    }
  },
  "aws.htbp.eks.access_entries_authentication": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Reads accessConfig.authenticationMode: API passes, CONFIG_MAP fails and mixed mode requires review."
    },
    "remediation_fields": {
      "summary": "Migrate required identity mappings to access entries and review creator privileges before completing the switch.",
      "steps": [
        "Migrate required identity mappings to access entries and review creator privileges before completing the switch."
      ],
      "caveats": [
        "Mixed API_AND_CONFIG_MAP mode remains manual; this does not enumerate all effective Kubernetes permissions."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EKS cluster authenticates through CONFIG_MAP mode.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "eks_cluster",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "closure": {},
      "delegates": [
        {
          "qualname": "eks_authentication_mode"
        }
      ]
    }
  },
  "aws.htbp.ecs.exec_session_logging_not_disabled": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Reads executeCommandConfiguration.logging and flags explicit NONE; omitted mode defaults to DEFAULT."
    },
    "remediation_fields": {
      "summary": "Enable suitable ECS Exec session logging and verify the intended task logging configuration.",
      "steps": [
        "Enable suitable ECS Exec session logging and verify the intended task logging configuration."
      ],
      "caveats": [
        "DEFAULT depends on task awslogs settings; this check does not establish transcript delivery."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "ECS Exec session logging is explicitly disabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ecs_cluster",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "closure": {},
      "delegates": [
        {
          "qualname": "ecs_exec_logging"
        }
      ]
    }
  },
  "aws.htbp.ecs.no_sensitive_host_mounts": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Joins declared host-volume source paths with container mounts and matches the sensitive-path list."
    },
    "remediation_fields": {
      "summary": "Remove unnecessary sensitive host mounts and tightly constrain the agents that require them.",
      "steps": [
        "Remove unnecessary sensitive host mounts and tightly constrain the agents that require them."
      ],
      "caveats": [
        "Read-only mounts are still flagged; declared paths do not prove successful runtime access."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An ECS container mounts a sensitive host path or runtime socket.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "ecs_task_definition",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "closure": {},
      "delegates": [
        {
          "qualname": "ecs_host_mounts"
        }
      ]
    }
  },
  "aws.htbp.lambda.runtime_updates_not_pinned_manual": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Reads RuntimeManagement.UpdateRuntimeOn and flags Manual."
    },
    "remediation_fields": {
      "summary": "Use Auto or FunctionUpdate unless a deliberate rollback requires manual pinning.",
      "steps": [
        "Use Auto or FunctionUpdate unless a deliberate rollback requires manual pinning."
      ],
      "caveats": [
        "Confirmed absent configuration is not applicable; current support and actual patch level are separate."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Lambda runtime management mode is Manual.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "closure": {},
      "delegates": [
        {
          "qualname": "runtime_pinning"
        }
      ]
    }
  },
  "aws.htbp.lambda.env_var_names_not_credentials": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Matches collected environment-variable names against credential patterns, excluding recognized reference names."
    },
    "remediation_fields": {
      "summary": "Confirm whether the named variables hold secrets and move actual secrets to suitable managed storage.",
      "steps": [
        "Confirm whether the named variables hold secrets and move actual secrets to suitable managed storage."
      ],
      "caveats": [
        "This is a name heuristic; values are not collected and a match does not prove a secret is present."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Lambda environment-variable names resemble literal credentials.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "closure": {},
      "delegates": [
        {
          "qualname": "env_var_names"
        }
      ]
    }
  },
  "aws_cis_ec2_default_security_group_not_attached": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Joins every attached interface group to same-VPC inventory and flags groups named default."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Use application-specific groups where needed and preserve required traffic when replacing attachments.",
      "steps": [
        "Use application-specific groups where needed and preserve required traffic when replacing attachments."
      ],
      "caveats": [
        "Group identity alone does not establish permissive rules; missing group inventory remains undetermined."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS EC2 ec2 security",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An attached EC 2 network interface uses the default security group.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "no_default_group",
      "closure": {},
      "delegates": []
    }
  },
  "aws_g6_ec2_instance_no_public_ipv6": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Parses assigned interface IPv6 addresses and flags globally routable addresses."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Review global IPv6 assignments and restrict intended listeners before removing unneeded addresses.",
      "steps": [
        "Review global IPv6 assignments and restrict intended listeners before removing unneeded addresses."
      ],
      "caveats": [
        "This checks allocation only; routes, ingress permissions and listeners are separate."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS EC2 ec2 security",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The EC 2 instance has a globally routable IPv6 address assigned.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "no_global_ipv6",
      "closure": {},
      "delegates": []
    }
  },
  "aws_nist_s3_bucket_cross_region_replication_enabled": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Resolves enabled replication destinations to collected bucket Regions and requires one different from the source."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Configure cross-Region replication where recovery needs it and verify destination protection.",
      "steps": [
        "Configure cross-Region replication where recovery needs it and verify destination protection."
      ],
      "caveats": [
        "External or unresolved destinations remain undetermined; replication success and recovery are not measured."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS S3 replication",
          "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The bucket has no resolved enabled replication rule to another Region.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "cross_region_replication",
      "closure": {},
      "delegates": []
    }
  },
  "aws_cis_lambda_execution_role_exists": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Resolves the declared execution-role ARN against complete same-account IAM role inventory."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Assign an existing suitable execution role and verify the function can use its required permissions.",
      "steps": [
        "Assign an existing suitable execution role and verify the function can use its required permissions."
      ],
      "caveats": [
        "Role trust, effective permissions and successful execution are separate."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS LAMBDA lambda intro execution role",
          "url": "https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The function execution role is absent from complete IAM role inventory.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "execution_role_exists",
      "closure": {},
      "delegates": []
    }
  },
  "aws_cis_lambda_execution_role_unique": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Checks active functions against account-wide execution-role usage with complete enabled-Region coverage for a pass."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Use a dedicated execution role where function isolation requires it and narrow its permissions.",
      "steps": [
        "Use a dedicated execution role where function isolation requires it and narrow its permissions."
      ],
      "caveats": [
        "Known sharing fails even with partial inventory; a unique role alone does not prove least privilege."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS LAMBDA lambda intro execution role",
          "url": "https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The active Lambda function shares its execution role with another active function.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "execution_role_unique",
      "closure": {},
      "delegates": []
    }
  },
  "aws_nist_autoscaling_use_multiple_instance_types_in_multiple_az": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Requires two Availability Zones and two distinct explicit MixedInstancesPolicy override instance types."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Use multiple zones and suitable instance-type alternatives where resilience requires them.",
      "steps": [
        "Use multiple zones and suitable instance-type alternatives where resilience requires them."
      ],
      "caveats": [
        "Attribute-based instance requirements remain undetermined; this does not test actual capacity availability."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS EC2 ec2 security",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The Auto Scaling group lacks two zones or two explicit instance-type choices.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "autoscaling_group",
      "predicate_qualname": "callback.<locals>.evaluate",
      "closure": {
        "kind": "autoscaling_group"
      },
      "delegates": [
        {
          "qualname": "autoscaling"
        }
      ]
    }
  },
  "aws_ecs_task_definition_credential_environment_names": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Checks complete task definitions for environment names matching the fixed AWS credential-name set."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Remove literal credential variables when present and use a narrowly scoped task role or secret references.",
      "steps": [
        "Remove literal credential variables when present and use a narrowly scoped task role or secret references."
      ],
      "caveats": [
        "Only names are assessed; actual secret values and runtime credential use are not proven."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS ECS security",
          "url": "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An ECS container declares an AWS credential environment-variable name.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ecs_task_definition",
      "predicate_qualname": "ecs_credential_environment_names",
      "closure": {},
      "delegates": []
    }
  },
  "aws_fedramp_emr_master_no_public_ip": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Joins the selected primary master to EC2 interfaces and flags public IPv4 or global IPv6 assignments."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Keep master-node addressing private where required and preserve administrative access through controlled paths.",
      "steps": [
        "Keep master-node addressing private where required and preserve administrative access through controlled paths."
      ],
      "caveats": [
        "Only running or waiting clusters apply; incomplete joins remain undetermined and network reachability is not probed."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS EMR emr manage view security groups",
          "url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-manage-view-security-groups.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An assessed EMR master node has a public address assigned.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "emr_cluster",
      "predicate_qualname": "callback",
      "closure": {},
      "delegates": []
    }
  },
  "aws.nist.emr_master_nodes_no_public_ip": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Joins all reported master instances to EC2 interfaces and flags public IPv4 or global IPv6 assignments."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Keep master-node addressing private where required and preserve administrative access through controlled paths.",
      "steps": [
        "Keep master-node addressing private where required and preserve administrative access through controlled paths."
      ],
      "caveats": [
        "Only running or waiting clusters apply; incomplete joins remain undetermined and network reachability is not probed."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS EMR emr manage view security groups",
          "url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-manage-view-security-groups.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An assessed EMR master node has a public address assigned.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "emr_cluster",
      "predicate_qualname": "callback",
      "closure": {},
      "delegates": []
    }
  },
  "aws_nist_emr_cluster_master_nodes_no_public_ip": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Joins all reported master instances to EC2 interfaces and flags public IPv4 or global IPv6 assignments."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Keep master-node addressing private where required and preserve administrative access through controlled paths.",
      "steps": [
        "Keep master-node addressing private where required and preserve administrative access through controlled paths."
      ],
      "caveats": [
        "Only running or waiting clusters apply; incomplete joins remain undetermined and network reachability is not probed."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS EMR emr manage view security groups",
          "url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-manage-view-security-groups.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An assessed EMR master node has a public address assigned.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "emr_cluster",
      "predicate_qualname": "callback",
      "closure": {},
      "delegates": []
    }
  },
  "aws_g6_emr_master_nodes_no_public_address": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Joins all reported master instances to EC2 interfaces and flags public IPv4 or global IPv6 assignments."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Keep master-node addressing private where required and preserve administrative access through controlled paths.",
      "steps": [
        "Keep master-node addressing private where required and preserve administrative access through controlled paths."
      ],
      "caveats": [
        "Only running or waiting clusters apply; incomplete joins remain undetermined and network reachability is not probed."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS EMR emr manage view security groups",
          "url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-manage-view-security-groups.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An assessed EMR master node has a public address assigned.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "emr_cluster",
      "predicate_qualname": "callback",
      "closure": {},
      "delegates": []
    }
  },
  "aws.pci.s3.bucket_backup_plan": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Requires an explicit non-excluded bucket ARN in an active scheduled backup selection with complete enabled-Region coverage."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Include the bucket in the intended scheduled backup plan and verify suitable recovery points.",
      "steps": [
        "Include the bucket in the intended scheduled backup plan and verify suitable recovery points."
      ],
      "caveats": [
        "Wildcard or conditional selections remain undetermined; plan membership does not demonstrate a successful backup."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS S3 replication",
          "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "No qualifying explicit scheduled backup selection includes the bucket.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "bucket_backup_plan",
      "closure": {},
      "delegates": []
    }
  },
  "aws_cis_beanstalk_persistent_logs_s3": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Requires LogPublicationControl=true and a resolved S3 log bucket and prefix for an active environment."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Enable required persistent log publication and resolve its intended S 3 destination.",
      "steps": [
        "Enable required persistent log publication and resolve its intended S 3 destination."
      ],
      "caveats": [
        "Terminating environments are not applicable; actual delivery and retention are not measured."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS S3 replication",
          "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "Beanstalk log publication is disabled or its S 3 destination is unresolved.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "elastic_beanstalk_environment",
      "predicate_qualname": "_evaluate",
      "closure": {},
      "delegates": [
        {
          "qualname": "_persistent_logs"
        }
      ]
    }
  },
  "aws_cis_ec2_userdata_embedded_secrets": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Validates the collected instance-bound user-data secret-indicator projection and flags recognized high-confidence categories."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Remove confirmed embedded secrets and rotate exposed credentials after migrating consumers.",
      "steps": [
        "Remove confirmed embedded secrets and rotate exposed credentials after migrating consumers."
      ],
      "caveats": [
        "Only projected categories are returned; raw user data and secret values are not exposed."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS EC2 ec2 security",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The user-data projection reports high-confidence embedded secret indicators.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "userdata_embedded_secrets",
      "closure": {},
      "delegates": []
    }
  },
  "aws_cis_elasticbeanstalk_https_listener": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Requires associated load balancers to declare certificate-backed TLS and redirect plain listeners to HTTPS."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Configure suitable TLS listeners and redirect or remove unnecessary plain listeners.",
      "steps": [
        "Configure suitable TLS listeners and redirect or remove unnecessary plain listeners."
      ],
      "caveats": [
        "No active associated load balancer is not applicable; certificate validity and actual routing are not tested."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS ELASTICBEANSTALK using features.logging S3.title",
          "url": "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/using-features.loggingS3.title.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An associated Beanstalk load balancer lacks required TLS or permits plain forwarding.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "elastic_beanstalk_environment",
      "predicate_qualname": "_evaluate",
      "closure": {},
      "delegates": [
        {
          "qualname": "_https_listener"
        }
      ]
    }
  },
  "aws_cis_elasticbeanstalk_load_balancer_access_logs": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Reads the access-log enabled attribute for every associated active load balancer."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Enable required load-balancer access logs and protect their intended S 3 destination.",
      "steps": [
        "Enable required load-balancer access logs and protect their intended S 3 destination."
      ],
      "caveats": [
        "This checks enabled declarations, not delivery, destination security or retention."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS ELASTICBEANSTALK using features.logging S3.title",
          "url": "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/using-features.loggingS3.title.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An associated Beanstalk load balancer has access logging disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "elastic_beanstalk_environment",
      "predicate_qualname": "_evaluate",
      "closure": {},
      "delegates": [
        {
          "qualname": "_lb_access_logs"
        }
      ]
    }
  },
  "aws_cis_lambda_execution_role_no_admin": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Requires a complete role-bound effective-policy projection and flags unconditional action/resource wildcard administration."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Remove unnecessary administrator grants from the execution role and retain required function permissions.",
      "steps": [
        "Remove unnecessary administrator grants from the execution role and retain required function permissions."
      ],
      "caveats": [
        "Incomplete policy, boundary, session or organization constraint analysis remains undetermined."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS LAMBDA lambda intro execution role",
          "url": "https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The Lambda execution-role projection establishes unconditional administrator access.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "_evaluate",
      "closure": {},
      "delegates": [
        {
          "qualname": "_admin"
        }
      ]
    }
  },
  "aws_cis_lightsail_ssm_patch_compliance": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Verifies the Lightsail-to-SSM mapping and flags positive MissingCount, FailedCount or InstalledRejectedCount values."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Resolve the reported missing, failed or rejected patches using the workload patch process.",
      "steps": [
        "Resolve the reported missing, failed or rejected patches using the workload patch process."
      ],
      "caveats": [
        "Malformed counts or unverified instance mappings remain undetermined; patch freshness is not assessed."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS EC2 ec2 security",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "SSM reports missing, failed or rejected patches for the matched Lightsail instance.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lightsail_instance",
      "predicate_qualname": "lightsail_patch",
      "closure": {},
      "delegates": []
    }
  },
  "aws_cis_s3_macie_classification_coverage": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Checks regional Macie enablement and automated discovery or a running/completed classification job selecting this bucket."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Enable appropriate discovery or configure a classification job covering the intended bucket.",
      "steps": [
        "Enable appropriate discovery or configure a classification job covering the intended bucket."
      ],
      "caveats": [
        "Selection does not prove every object was analyzed; unresolved job criteria remain undetermined."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS S3 replication",
          "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "No qualifying Macie discovery or classification-job configuration covers the bucket.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "macie_classification_coverage",
      "closure": {},
      "delegates": []
    }
  },
  "aws_ebs_snapshot_trusted_accounts": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Compares snapshot create-volume grants with the explicitly supplied trusted-account allowlist and flags public grants."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Review external grants and restrict snapshot sharing to intended recipients.",
      "steps": [
        "Review external grants and restrict snapshot sharing to intended recipients."
      ],
      "caveats": [
        "This historical custom-policy check cannot infer trusted third parties from read-only cloud configuration."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS EC2 ec2 security",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The snapshot grants access outside the supplied trusted-account allowlist.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ebs_snapshot",
      "predicate_qualname": "check_aws_ebs_snapshot_trusted_accounts",
      "closure": {},
      "delegates": []
    }
  },
  "aws_ec2_instance_time_offset_monitored": {
    "batch": "final-native30",
    "description_fields": {
      "description": "For running instances, checks the bound CWAgent time_offset sample is within 1000 milliseconds and 24 hours old."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Investigate excessive clock offset or restore current time-offset telemetry.",
      "steps": [
        "Investigate excessive clock offset or restore current time-offset telemetry."
      ],
      "caveats": [
        "Future, missing or mismatched samples remain undetermined; this does not directly query the operating-system clock."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS EC2 ec2 security",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The EC 2 time-offset sample exceeds the offset or freshness threshold.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_make.<locals>.evaluate",
      "closure": {
        "cid": "aws_ec2_instance_time_offset_monitored"
      },
      "delegates": [
        {
          "qualname": "_ec2_time"
        }
      ]
    }
  },
  "aws_g6_ecs_fargate_storage_encryption": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Joins service launch-volume configurations and task EFS references, requiring encryption on associated managed EBS and EFS storage."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Enable encryption on the identified storage and migrate safely when replacement is required.",
      "steps": [
        "Enable encryption on the identified storage and migrate safely when replacement is required."
      ],
      "caveats": [
        "This source criterion assesses associated storage declarations, not all Fargate ephemeral storage or effective key authorization."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS ECS security",
          "url": "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An assessed ECS service volume uses unencrypted managed EBS or EFS storage.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ecs_cluster",
      "predicate_qualname": "_install.<locals>.check",
      "closure": {
        "identifier": "aws_g6_ecs_fargate_storage_encryption"
      },
      "delegates": [
        {
          "qualname": "_ecs"
        }
      ]
    }
  },
  "aws_g6_efs_effective_backup_plan_selection": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Matches enabled backup-plan selections using resource patterns, exclusions and supported tag conditions; requires a declared IAM role."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Include the filesystem in the required backup selection and verify suitable recovery points.",
      "steps": [
        "Include the filesystem in the required backup selection and verify suitable recovery points."
      ],
      "caveats": [
        "A matching selection does not prove role usability, completed backups or successful restoration."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS EFS awsbackup",
          "url": "https://docs.aws.amazon.com/efs/latest/ug/awsbackup.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "No qualifying enabled backup-plan selection matches the EFS filesystem.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "_evaluate",
      "closure": {},
      "delegates": [
        {
          "qualname": "<lambda>"
        }
      ]
    }
  },
  "aws_nist_ec2_instance_not_publicly_accessible": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Requires complete route, ingress, target and listener projections, then flags public paths with all three access conditions true."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Restrict unnecessary public listeners or ingress sources while preserving intended access.",
      "steps": [
        "Restrict unnecessary public listeners or ingress sources while preserving intended access."
      ],
      "caveats": [
        "This uses the collected reachability projection; it does not send packets or establish application authentication."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS EC2 ec2 security",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The EC 2 reachability projection reports a complete permitted public path.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_make.<locals>.evaluate",
      "closure": {
        "cid": "aws_nist_ec2_instance_not_publicly_accessible"
      },
      "delegates": [
        {
          "qualname": "_ec2_public"
        }
      ]
    }
  },
  "aws_nist_efs_file_system_in_backup_plan": {
    "batch": "final-native30",
    "description_fields": {
      "description": "Matches enabled backup-plan selections using resource patterns, exclusions and supported tag conditions."
    },
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Include the filesystem in the required backup selection and verify suitable recovery points.",
      "steps": [
        "Include the filesystem in the required backup selection and verify suitable recovery points."
      ],
      "caveats": [
        "A matching selection does not prove role usability, completed backups or successful restoration."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS EFS awsbackup",
          "url": "https://docs.aws.amazon.com/efs/latest/ug/awsbackup.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "No qualifying enabled backup-plan selection matches the EFS filesystem.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "_evaluate",
      "closure": {},
      "delegates": [
        {
          "qualname": "<lambda>"
        }
      ]
    }
  }
}
''')


def _apply(cid,original,kind):
    row=ROWS.get(cid)
    if row is None:
        return deepcopy(original)
    if kind=="remediation" and row["new_text_only_template"]:
        current={}
    else:
        current=deepcopy(original) if isinstance(original,dict) else {}
    current.update(deepcopy(row[kind+"_fields"]))
    return current


def description(cid,original):
    return _apply(cid,original,"description")


def remediation(cid,original):
    return _apply(cid,original,"remediation")


REVIEWED_RISKS={cid:(row["reviewed_source_severity"],row["reviewed_severity"]) for cid,row in ROWS.items()}
