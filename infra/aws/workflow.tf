locals {
  worker_env = {
    PEASO_AI_CREDENTIAL_SECRET_ARN       = aws_secretsmanager_secret.ai.arn
    CODEX_TOKEN_SECRET_ARN               = var.codex_token_secret_arn
    PEASO_AWS_COLLECTOR_ROLE_ARN         = aws_iam_role.customer_trust.arn
    PEASO_PLATFORM_ACCOUNT_IDS           = join(",", distinct(concat([var.account_id], var.platform_account_ids)))
    PEASO_GCP_PLATFORM_PROJECT           = var.gcp_platform_project
    PEASO_GCP_PLATFORM_EMAIL             = var.gcp_platform_email
    PEASO_AUTH_MODE                      = "cognito"
    PEASO_COGNITO_ISSUER                 = local.issuer
    PEASO_COGNITO_CLIENT_ID              = local.client_id
    PEASO_STORAGE                        = "dynamodb"
    PEASO_DYNAMODB_TABLE                 = aws_dynamodb_table.metadata.name
    PEASO_WORK_STATE_INDEX               = "work-state"
    PEASO_SCHEDULE_TIME_INDEX            = "schedule-time"
    PEASO_ARTIFACT_BUCKET                = aws_s3_bucket.artifacts.id
    PEASO_SCAN_TIMEOUT_SECONDS           = tostring(var.scan_runtime_limits.workflow_seconds)
    PEASO_COLLECTOR_VCPU                 = tostring(var.worker_resources.collector.cpu / 1024)
    PEASO_COLLECTOR_MEMORY_GIB           = tostring(var.worker_resources.collector.memory / 1024)
    PEASO_ANALYZER_VCPU                  = tostring(var.worker_resources.analyzer.cpu / 1024)
    PEASO_ANALYZER_MEMORY_GIB            = tostring(var.worker_resources.analyzer.memory / 1024)
    PEASO_STATE_DIR                      = "/tmp/peaso/state"
    PEASO_IDENTITY_DIR                   = "/tmp/peaso/identity"
    AWS_DEFAULT_REGION                   = var.region
    PEASO_SOURCE_VERSION                 = var.source_version
    PEASO_HARDENING_NATIVE_FINAL_ENABLED = "1"
    PEASO_AI_HARDENING_AGENT_ENABLED     = "0"
    PEASO_AI_EXPOSURE_AGENT_ENABLED      = "0"
  }
  task_roles = { collector = aws_iam_role.collector.arn, analyzer = aws_iam_role.analyzer.arn }
}
resource "aws_ecs_task_definition" "tasks" {
  for_each                 = local.task_roles
  family                   = "${local.name}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.worker_resources[each.key].cpu)
  memory                   = tostring(var.worker_resources[each.key].memory)
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = each.value
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  container_definitions = jsonencode([{
    name                   = each.key
    image                  = var.worker_image
    essential              = true
    entryPoint             = ["python", "-m", "peaso.worker"]
    command                = [each.key, "--once"]
    user                   = "10001:10001"
    readonlyRootFilesystem = true
    mountPoints            = [{ sourceVolume = "scratch", containerPath = "/tmp", readOnly = false }]
    linuxParameters        = { capabilities = { add = [], drop = ["ALL"] } }
    portMappings           = []
    volumesFrom            = []
    systemControls         = []
    stopTimeout            = 30
    environment = [for key, value in merge(local.worker_env, {
      PEASO_TASK_VCPU       = tostring(var.worker_resources[each.key].cpu / 1024)
      PEASO_TASK_MEMORY_GIB = tostring(var.worker_resources[each.key].memory / 1024)
      }, each.key == "collector" ? {
      PEASO_CREDENTIAL_SECRET_ARN      = aws_secretsmanager_secret.credentials.arn
      PEASO_GCP_PLATFORM_SA_SECRET_ARN = var.gcp_platform_sa_secret_arn
    } : local.ai_runtime_env) : { name = key, value = value }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.tasks.name
        awslogs-region        = var.region
        awslogs-stream-prefix = each.key
      }
    }
  }])
  volume { name = "scratch" }
  depends_on = [aws_iam_role_policy.collector, aws_iam_role_policy.customer_trust]
}
locals {
  run_tasks = { for stage in ["collector", "analyzer"] : stage => {
    Type           = "Task"
    Resource       = "arn:aws:states:::ecs:runTask.sync"
    TimeoutSeconds = stage == "analyzer" ? var.scan_runtime_limits.workflow_seconds : var.scan_runtime_limits.stage_seconds
    Parameters = {
      Cluster         = aws_ecs_cluster.cspm.arn
      TaskDefinition  = aws_ecs_task_definition.tasks[stage].arn
      LaunchType      = "FARGATE"
      PlatformVersion = "1.4.0"
      NetworkConfiguration = {
        AwsvpcConfiguration = {
          Subnets        = [aws_subnet.tasks.id]
          SecurityGroups = [aws_security_group.tasks.id]
          AssignPublicIp = "ENABLED"
        }
      }
      Overrides = {
        ContainerOverrides = [{
          Name        = stage
          "Command.$" = stage == "collector" ? "States.Array('collector', '--once', '--tenant-id', $.tenant_id, '--scan-id', $.scan_id)" : "States.Array('analyzer', '--progressive', '--once', '--tenant-id', $.tenant_id, '--scan-id', $.scan_id)"
        }]
      }
    }
    ResultPath = null
    Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.failure", Next = stage == "collector" ? "CollectorBranchFailed" : "AnalyzerBranchFailed" }]
    Next       = stage == "collector" ? "ReadCollectedStatus" : "ReadCompletedStatus"
  } }
  read_job_status = {
    Type     = "Task"
    Resource = "arn:aws:states:::dynamodb:getItem"
    Parameters = {
      TableName                = aws_dynamodb_table.metadata.name
      Key                      = { PK = { "S.$" = "States.Format('tenant/{}', $.tenant_id)" }, SK = { "S.$" = "States.Format('job/{}', $.scan_id)" } }
      ConsistentRead           = true
      ProjectionExpression     = "#status"
      ExpressionAttributeNames = { "#status" = "status" }
    }
    ResultPath = "$.job_status"
    Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.failure", Next = "ReleaseFailed" }]
  }
  mark_failed = {
    Type          = "Task"
    Resource      = "arn:aws:states:::dynamodb:updateItem"
    QueryLanguage = "JSONata"
    Arguments = {
      TableName                = aws_dynamodb_table.metadata.name
      Key                      = { PK = { S = "{% 'tenant/' & $states.input.tenant_id %}" }, SK = { S = "{% 'job/' & $states.input.scan_id %}" } }
      UpdateExpression         = "SET #status=:failed, #owner=:null, lease=:null, #error=:error, error_code=:code, error_stage=:stage, #history=list_append(if_not_exists(#history,:empty),:event) ADD #rev :one"
      ConditionExpression      = "attribute_exists(PK) AND #status IN (:queued,:collecting,:collected,:analyzing)"
      ExpressionAttributeNames = { "#status" = "status", "#owner" = "owner", "#error" = "error", "#history" = "history", "#rev" = "rev" }
      ExpressionAttributeValues = {
        ":failed" = { S = "failed" }, ":null" = { NULL = true }, ":one" = { N = "1" }
        ":error"  = { S = "Hosted scan did not complete; check worker capacity and connector access" }
        ":code"   = { S = "{% $exists($states.input.task_failure.code) ? $states.input.task_failure.code : 'workflow_failed' %}" }
        ":stage"  = { S = "{% $exists($states.input.task_failure.stage) ? $states.input.task_failure.stage : 'workflow' %}" }
        ":queued" = { S = "queued" }, ":collecting" = { S = "collecting" }, ":collected" = { S = "collected" }, ":analyzing" = { S = "analyzing" }
        ":empty"  = { L = [] }, ":event" = { L = [{ M = { status = { S = "failed" }, at = { S = "{% $now() %}" } } }] }
      }
    }
    Output = "{% $states.input %}"
    Catch  = [{ ErrorEquals = ["DynamoDB.ConditionalCheckFailedException"], Output = "{% $states.input %}", Next = "ReadFailureStatus" }]
    Next   = "Failed"
  }
}
resource "aws_sfn_state_machine" "scan" {
  name     = local.name
  role_arn = aws_iam_role.workflow.arn
  type     = "STANDARD"
  definition = jsonencode({
    Comment        = "Bounded collection and progressive analysis run concurrently with separate credentials"
    StartAt        = "ScanStages"
    TimeoutSeconds = var.scan_runtime_limits.workflow_seconds
    States = {
      ScanStages = {
        Type       = "Parallel"
        ResultPath = null
        Branches = [
          {
            StartAt = "Collect"
            States = {
              Collect = local.run_tasks.collector
              ReadCollectedStatus = merge(local.read_job_status, {
                Next  = "CollectedStatus"
                Catch = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.failure", Next = "CollectorBranchFailed" }]
              })
              CollectedStatus = {
                Type = "Choice"
                # The analyzer may claim or complete just before this read.
                Choices = [for status in ["collected", "analyzing", "completed"] : {
                  Variable = "$.job_status.Item.status.S", StringEquals = status, Next = "CollectorSucceeded"
                }]
                Default = "CollectorBranchFailed"
              }
              CollectorBranchFailed = { Type = "Fail", Error = "CollectorBranchFailed", Cause = "Collector task did not complete" }
              CollectorSucceeded    = { Type = "Succeed" }
            }
          },
          {
            StartAt = "Analyze"
            States = {
              Analyze = local.run_tasks.analyzer
              ReadCompletedStatus = merge(local.read_job_status, {
                Next  = "CompletedStatus"
                Catch = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.failure", Next = "AnalyzerBranchFailed" }]
              })
              CompletedStatus = {
                Type    = "Choice"
                Choices = [{ Variable = "$.job_status.Item.status.S", StringEquals = "completed", Next = "AnalyzerSucceeded" }]
                Default = "AnalyzerBranchFailed"
              }
              AnalyzerBranchFailed = { Type = "Fail", Error = "AnalyzerBranchFailed", Cause = "Analyzer task did not complete" }
              AnalyzerSucceeded    = { Type = "Succeed" }
            }
          },
        ]
        Catch = [
          { ErrorEquals = ["CollectorBranchFailed"], ResultPath = "$.failure", Next = "CollectorTaskFailed" },
          { ErrorEquals = ["AnalyzerBranchFailed"], ResultPath = "$.failure", Next = "AnalyzerTaskFailed" },
          { ErrorEquals = ["States.ALL"], ResultPath = "$.failure", Next = "ParallelTaskFailed" },
        ]
        Next = "ReleaseSucceeded"
      }
      CollectorTaskFailed = {
        Type = "Pass", Result = { code = "worker_task_failed", stage = "collector" }, ResultPath = "$.task_failure", Next = "ReleaseFailed"
      }
      AnalyzerTaskFailed = {
        Type = "Pass", Result = { code = "worker_task_failed", stage = "analyzer" }, ResultPath = "$.task_failure", Next = "ReleaseFailed"
      }
      ParallelTaskFailed = {
        Type = "Pass", Result = { code = "workflow_failed", stage = "workflow" }, ResultPath = "$.task_failure", Next = "ReleaseFailed"
      }
      # The worker releases its durable admission on terminal transition. A
      # scheduler sweep reconciles abnormal workflow exits and lease loss.
      ReleaseSucceeded = { Type = "Pass", Next = "Succeeded" }
      ReleaseFailed    = { Type = "Pass", Next = "ReadFailureStatus" }
      ReadFailureStatus = merge(local.read_job_status, {
        Next = "FailureStatus", Catch = [{ ErrorEquals = ["States.ALL"], ResultPath = null, Next = "MarkFailed" }]
      })
      FailureStatus = {
        Type = "Choice"
        Choices = [
          { Variable = "$.job_status.Item.status.S", IsPresent = false, Next = "Failed" },
          { Variable = "$.job_status.Item.status.S", StringEquals = "cancelled", Next = "Cancelled" },
          { Variable = "$.job_status.Item.status.S", StringEquals = "completed", Next = "Succeeded" },
          { Variable = "$.job_status.Item.status.S", StringEquals = "failed", Next = "Failed" },
          { Variable = "$.job_status.Item.status.S", StringEquals = "timed_out", Next = "Failed" },
          { Variable = "$.job_status.Item.status.S", StringEquals = "queue_exhausted", Next = "Failed" },
          { Variable = "$.job_status.Item.status.S", StringEquals = "credentials_expired", Next = "Failed" },
        ]
        Default = "MarkFailed"
      }
      MarkFailed = local.mark_failed
      Succeeded  = { Type = "Succeed" }
      Cancelled  = { Type = "Succeed" }
      Failed     = { Type = "Fail", Error = "ScanTaskFailed", Cause = "The bounded scan did not complete" }
    }
  })
  depends_on = [aws_iam_role_policy.workflow, aws_iam_role_policy.execution, aws_iam_role_policy.collector, aws_iam_role_policy.analyzer, aws_route_table_association.tasks]
}
