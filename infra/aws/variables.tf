variable "region" {
  type    = string
  default = "us-east-1"
  validation {
    condition     = var.region == "us-east-1"
    error_message = "This stack requires its identity and CloudFront certificate in us-east-1."
  }
}
variable "api_zip" {
  type        = string
  description = "Absolute path to the built Linux x86_64 FastAPI/Mangum ZIP."
}
variable "source_version" {
  type        = string
  default     = "unreleased"
  description = "SHA256 manifest of the exact frozen source used to build the release."
  validation {
    condition     = var.source_version == "unreleased" || can(regex("^[a-f0-9]{64}$", var.source_version))
    error_message = "Release source version must be a SHA256 manifest digest."
  }
}
variable "worker_image" {
  type        = string
  description = "Published CSPM-only collector/analyzer image pinned by sha256 digest."
  validation {
    condition     = can(regex("^[0-9]{12}\\.dkr\\.ecr\\.us-east-1\\.amazonaws\\.com/hacktricks-cspm-worker@sha256:[a-f0-9]{64}$", var.worker_image))
    error_message = "Use the dedicated CSPM ECR repository and an immutable digest."
  }
}
variable "enable_public_customer_role_template" {
  type        = bool
  default     = false
  description = "Opt in only after checking account-level S3 Block Public Access. A private CloudFront download remains available by default."
}
variable "gcp_platform_sa_secret_arn" {
  type        = string
  default     = ""
  description = "Existing Secrets Manager secret ARN containing the HackTricks CSPM GCP service account JSON. The value never enters Terraform state."
  validation {
    condition     = var.gcp_platform_sa_secret_arn == "" || can(regex("^arn:aws:secretsmanager:us-east-1:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$", var.gcp_platform_sa_secret_arn))
    error_message = "Use a secret in the dedicated CSPM AWS account and region."
  }
}
variable "worker_resources" {
  type = map(object({ cpu = number, memory = number }))
  default = {
    collector = { cpu = 4096, memory = 16384 }
    analyzer  = { cpu = 1024, memory = 8192 }
  }
  description = "Prospective Linux/x86 Fargate CPU units and MiB: collector 4 vCPU/16 GiB, analyzer 1 vCPU/8 GiB. A 1 vCPU collector was CPU-bound on offline content detection and AWS TLS reads; four content lanes need four vCPUs. Not an all-estates capacity guarantee."
  validation {
    condition = toset(keys(var.worker_resources)) == toset(["collector", "analyzer"]) && alltrue([
      for resource in values(var.worker_resources) :
      (resource.cpu == 512 && contains([1024, 2048, 3072, 4096], resource.memory)) ||
      (resource.cpu == 1024 && contains([2048, 3072, 4096, 5120, 6144, 7168, 8192], resource.memory)) ||
      (resource.cpu == 2048 && resource.memory >= 4096 && resource.memory <= 16384 && resource.memory % 1024 == 0) ||
      (resource.cpu == 4096 && resource.memory >= 8192 && resource.memory <= 30720 && resource.memory % 1024 == 0)
    ]) && try(var.worker_resources.collector.memory >= 6144 && var.worker_resources.analyzer.memory >= 4096, false)
    error_message = "Specify collector and analyzer only, with supported 0.5/1/2/4 vCPU Fargate sizes; prospective collection needs at least 6 GiB and analysis at least 4 GiB."
  }
}
variable "scan_runtime_limits" {
  type = object({ workflow_seconds = number, stage_seconds = number, lease_seconds = number })
  default = {
    workflow_seconds = 7200
    stage_seconds    = 7200
    lease_seconds    = 7500
  }
  description = "Bounded whole-job/workflow, per-ECS-stage and owned global lease durations. A stage may use the existing whole-workflow window for selected content scans."
  validation {
    condition = (
      var.scan_runtime_limits.workflow_seconds >= 900 && var.scan_runtime_limits.workflow_seconds <= 7200 &&
      var.scan_runtime_limits.stage_seconds >= 300 && var.scan_runtime_limits.stage_seconds <= 7200 &&
      var.scan_runtime_limits.stage_seconds <= var.scan_runtime_limits.workflow_seconds &&
      var.scan_runtime_limits.lease_seconds >= var.scan_runtime_limits.workflow_seconds + 300 &&
      var.scan_runtime_limits.lease_seconds <= 7500 &&
      alltrue([for value in values(var.scan_runtime_limits) : value == floor(value)])
    )
    error_message = "Use integer bounded job/workflow 900–7200s, stages 300–7200s within workflow, and an owned lease at least 300s longer (at most7500s)."
  }
}
variable "budget_email" {
  type        = string
  description = "Address receiving CSPM budget alerts."
}
variable "monthly_budget_usd" {
  type    = number
  default = 25
  validation {
    condition     = var.monthly_budget_usd >= 1 && var.monthly_budget_usd <= 100
    error_message = "Keep the dedicated CSPM monthly budget within $1-$100."
  }
}

variable "codex_token_secret_arn" {
  type        = string
  default     = ""
  description = "Optional runtime Secrets Manager ARN holding a plain Codex token or JSON access_token. Values are never read by Terraform."
  validation {
    condition     = var.codex_token_secret_arn == "" || can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$", var.codex_token_secret_arn))
    error_message = "Provide a Secrets Manager secret ARN or leave empty for personal sign-in."
  }
}
variable "codex_token_kms_key_arn" {
  type        = string
  default     = ""
  description = "Optional customer-managed KMS key used by the configured Codex secret."
}

variable "account_id" {
  type        = string
  description = "Explicit deployment account; the provider rejects other accounts."
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "Provide the deployment AWS account ID."
  }
}
variable "cognito_pool_id" {
  type        = string
  description = "Existing user pool supplied by private deployment configuration."
}
variable "cognito_client_id" {
  type        = string
  description = "Existing Cognito app client supplied by private deployment configuration."
}
variable "stripe_secret_arn" {
  type        = string
  description = "Existing billing secret ARN. Only runtime reads its value."
}
variable "stripe_price_id" {
  type        = string
  description = "Subscription price accepted by the hosted application."
}
variable "gcp_platform_project" {
  type        = string
  default     = ""
  description = "Project owning the optional hosted GCP service account."
}
variable "gcp_platform_email" {
  type        = string
  default     = ""
  description = "Optional hosted GCP service-account email."
}
variable "platform_account_ids" {
  type        = list(string)
  default     = []
  description = "Additional operator-owned AWS accounts excluded from customer connectors."
}

variable "archived_customer_role_templates" {
  type        = map(string)
  default     = {}
  description = "Private paths to prior immutable customer templates, keyed by original SHA256. Retain existing keys when upgrading a deployed stack."
  validation {
    condition     = alltrue([for digest, path in var.archived_customer_role_templates : can(regex("^[a-f0-9]{64}$", digest)) && filesha256(path) == digest])
    error_message = "Every private archive path must match its original SHA256 key."
  }
}
