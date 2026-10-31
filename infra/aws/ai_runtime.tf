# Agent tasks deliberately have NO task_role_arn. Execution-role credentials
# are used by ECS to pull the image, never injected into either container.
resource "aws_ecs_cluster" "ai" { name = "${local.name}-ai" }
resource "aws_cloudwatch_log_group" "ai_tasks" {
  name              = "/ecs/${local.name}-ai"
  retention_in_days = 7
}
resource "aws_iam_role" "ai_execution" {
  name               = "${local.name}-ai-task-execution"
  assume_role_policy = local.task_trust
}
resource "aws_iam_role_policy" "ai_execution" {
  role = aws_iam_role.ai_execution.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = "*" },
    { Effect = "Allow", Action = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"], Resource = aws_ecr_repository.worker.arn },
    { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.ai_tasks.arn}:*" }
  ] })
}
resource "aws_s3_bucket" "ai_transport" {
  bucket = "${local.name}-ai-transport-${local.account_id}"
}
resource "aws_s3_bucket_public_access_block" "ai_transport" {
  bucket                  = aws_s3_bucket.ai_transport.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "ai_transport" {
  bucket = aws_s3_bucket.ai_transport.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_lifecycle_configuration" "ai_transport" {
  bucket = aws_s3_bucket.ai_transport.id
  rule {
    id     = "remove-abandoned-ai-transport"
    status = "Enabled"
    filter { prefix = "invocations/" }
    expiration { days = 1 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}
resource "aws_s3_bucket_policy" "ai_transport" {
  bucket = aws_s3_bucket.ai_transport.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect    = "Deny", Principal = "*", Action = "s3:*",
    Resource  = [aws_s3_bucket.ai_transport.arn, "${aws_s3_bucket.ai_transport.arn}/*"],
    Condition = { Bool = { "aws:SecureTransport" = "false" } }
  }] })
}
resource "aws_ecs_task_definition" "ai" {
  family                   = "${local.name}-ai"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.ai_execution.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  container_definitions = jsonencode([for name in ["agent", "relay"] : {
    name                   = name
    image                  = var.worker_image
    essential              = true
    user                   = "10001:10001"
    readonlyRootFilesystem = true
    entryPoint             = ["python", "-m", "peaso.ai.task_runtime"]
    command                = [name]
    memory                 = name == "agent" ? 1792 : 256
    mountPoints            = [{ sourceVolume = "${name}-scratch", containerPath = "/tmp", readOnly = false }]
    linuxParameters        = { capabilities = { add = [], drop = ["ALL"] } }
    stopTimeout            = 10
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.ai_tasks.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "ai-${name}"
      }
    }
  }])
  volume { name = "agent-scratch" }
  volume { name = "relay-scratch" }
  depends_on = [aws_iam_role_policy.ai_execution]
}
resource "aws_iam_role_policy" "ai_dispatch" {
  role = aws_iam_role.analyzer.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    # AWS does not support resource-level authorization for this describe API.
    { Effect = "Allow", Action = ["ecs:DescribeTaskDefinition"], Resource = "*",
    Condition = { StringEquals = { "aws:RequestedRegion" = var.region } } },
    { Effect = "Allow", Action = ["ecs:RunTask"], Resource = aws_ecs_task_definition.ai.arn,
    Condition = { ArnEquals = { "ecs:cluster" = aws_ecs_cluster.ai.arn } } },
    { Effect   = "Allow", Action = ["ecs:DescribeTasks", "ecs:StopTask"],
      Resource = "arn:aws:ecs:${var.region}:${local.account_id}:task/${aws_ecs_cluster.ai.name}/*",
    Condition = { ArnEquals = { "ecs:cluster" = aws_ecs_cluster.ai.arn } } },
    { Effect = "Allow", Action = ["iam:PassRole"], Resource = aws_iam_role.ai_execution.arn,
    Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } } },
    { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
    Resource = "${aws_s3_bucket.ai_transport.arn}/invocations/*" }
  ] })
}
locals {
  ai_runtime_env = {
    PEASO_AI_RUNTIME                 = "fargate"
    PEASO_AI_FARGATE_CLUSTER         = aws_ecs_cluster.ai.arn
    PEASO_AI_FARGATE_TASK_DEFINITION = aws_ecs_task_definition.ai.arn
    PEASO_AI_FARGATE_SUBNETS         = aws_subnet.ai.id
    PEASO_AI_FARGATE_SECURITY_GROUPS = aws_security_group.ai.id
    PEASO_AI_FARGATE_BUCKET          = aws_s3_bucket.ai_transport.id
    PEASO_AI_MAX_CONCURRENCY         = "12"
    PEASO_AI_TIMEOUT_SECONDS         = "3000"
  }
}
