locals {
  runtime_env = merge(local.ai_runtime_env, {
    PEASO_AI_CREDENTIAL_SECRET_ARN          = aws_secretsmanager_secret.ai.arn
    CODEX_TOKEN_SECRET_ARN                  = var.codex_token_secret_arn
    PEASO_AWS_COLLECTOR_ROLE_ARN            = aws_iam_role.customer_trust.arn
    PEASO_PLATFORM_ACCOUNT_IDS              = join(",", distinct(concat([var.account_id], var.platform_account_ids)))
    PEASO_GCP_PLATFORM_PROJECT              = var.gcp_platform_project
    PEASO_GCP_PLATFORM_EMAIL                = var.gcp_platform_email
    PEASO_AUTH_MODE                         = "cognito"
    PEASO_COGNITO_ISSUER                    = local.issuer
    PEASO_COGNITO_CLIENT_ID                 = local.client_id
    PEASO_STORAGE                           = "dynamodb"
    PEASO_DYNAMODB_TABLE                    = aws_dynamodb_table.metadata.name
    PEASO_WORK_STATE_INDEX                  = "work-state"
    PEASO_SCHEDULE_TIME_INDEX               = "schedule-time"
    PEASO_ARTIFACT_BUCKET                   = aws_s3_bucket.artifacts.id
    PEASO_CREDENTIAL_SECRET_ARN             = aws_secretsmanager_secret.credentials.arn
    PEASO_GCP_PLATFORM_SA_SECRET_ARN        = var.gcp_platform_sa_secret_arn
    PEASO_REQUIRE_CONNECTOR_ACCESS_CHECK    = "true"
    PEASO_STRIPE_SECRET_ARN                 = local.stripe_arn
    PEASO_STRIPE_PRICE_ID                   = local.stripe_price
    PEASO_WORKFLOW_ARN                      = local.workflow_arn
    PEASO_ALLOWED_ORIGINS                   = "https://${local.domain}"
    PEASO_PUBLIC_CUSTOMER_ROLE_TEMPLATE_URL = var.enable_public_customer_role_template ? "https://${aws_s3_bucket.templates[0].bucket}.s3.${var.region}.amazonaws.com/${aws_s3_object.customer_role_template[local.customer_role_template_sha256].key}" : ""
    PEASO_SOURCE_VERSION                    = var.source_version
    PEASO_SOURCE_URL                        = "https://${local.domain}/source/peaso-source-${var.source_version}.zip"
    PEASO_SCAN_TIMEOUT_SECONDS              = tostring(var.scan_runtime_limits.workflow_seconds)
    PEASO_COLLECTOR_VCPU                    = tostring(var.worker_resources.collector.cpu / 1024)
    PEASO_COLLECTOR_MEMORY_GIB              = tostring(var.worker_resources.collector.memory / 1024)
    PEASO_ANALYZER_VCPU                     = tostring(var.worker_resources.analyzer.cpu / 1024)
    PEASO_ANALYZER_MEMORY_GIB               = tostring(var.worker_resources.analyzer.memory / 1024)
    PEASO_STATE_DIR                         = "/tmp/peaso/state"
    PEASO_IDENTITY_DIR                      = "/tmp/peaso/identity"
  })
}
resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/lambda/${local.name}-api"
  retention_in_days = 7
}
resource "aws_cloudwatch_log_group" "scheduler" {
  name              = "/aws/lambda/${local.name}-scheduler"
  retention_in_days = 7
}
resource "aws_lambda_function" "api" {
  function_name    = "${local.name}-api"
  role             = aws_iam_role.api.arn
  runtime          = "python3.12"
  architectures    = ["x86_64"]
  handler          = "peaso.server.lambda_handler.handler"
  filename         = null
  s3_bucket        = aws_s3_object.api_zip.bucket
  s3_key           = aws_s3_object.api_zip.key
  source_code_hash = filebase64sha256(var.api_zip)
  # Catalog data and native finding hydration can coexist in a warm API process.
  memory_size                    = 1792
  timeout                        = 28
  reserved_concurrent_executions = 10
  environment { variables = local.runtime_env }
  depends_on = [aws_iam_role_policy.api, aws_iam_role_policy.customer_trust, aws_cloudwatch_log_group.api, aws_secretsmanager_secret_version.credentials]
}
resource "aws_lambda_function" "scheduler" {
  function_name                  = "${local.name}-scheduler"
  role                           = aws_iam_role.api.arn
  runtime                        = "python3.12"
  architectures                  = ["x86_64"]
  handler                        = "peaso.server.scheduler_handler.handler"
  filename                       = null
  s3_bucket                      = aws_s3_object.api_zip.bucket
  s3_key                         = aws_s3_object.api_zip.key
  source_code_hash               = filebase64sha256(var.api_zip)
  memory_size                    = 256
  timeout                        = 60
  reserved_concurrent_executions = 1
  environment { variables = local.runtime_env }
  depends_on = [aws_iam_role_policy.api, aws_cloudwatch_log_group.scheduler, aws_secretsmanager_secret_version.credentials]
}
resource "aws_apigatewayv2_api" "cspm" {
  name          = local.name
  protocol_type = "HTTP"
}
resource "aws_apigatewayv2_integration" "api" {
  api_id                 = aws_apigatewayv2_api.cspm.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 29000
}
resource "aws_apigatewayv2_route" "api" {
  api_id    = aws_apigatewayv2_api.cspm.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.api.id}"
}
resource "aws_apigatewayv2_stage" "api" {
  api_id      = aws_apigatewayv2_api.cspm.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_burst_limit = 10
    throttling_rate_limit  = 5
  }
}
resource "aws_lambda_permission" "api" {
  statement_id  = "CspmHttpApi"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.cspm.execution_arn}/*/*"
}
resource "aws_cloudwatch_event_rule" "schedules" {
  name                = "${local.name}-schedules"
  schedule_expression = "rate(1 minute)"
}
resource "aws_cloudwatch_event_target" "schedules" {
  rule = aws_cloudwatch_event_rule.schedules.name
  arn  = aws_lambda_function.scheduler.arn
}
resource "aws_lambda_permission" "schedules" {
  statement_id  = "CspmScheduleTick"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scheduler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedules.arn
}
