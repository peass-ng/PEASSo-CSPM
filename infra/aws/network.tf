resource "aws_vpc" "cspm" {
  cidr_block           = "10.253.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = local.name }
}
resource "aws_internet_gateway" "cspm" { vpc_id = aws_vpc.cspm.id }
resource "aws_subnet" "tasks" {
  vpc_id                  = aws_vpc.cspm.id
  cidr_block              = "10.253.0.0/26"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false
}
resource "aws_route_table" "tasks" {
  vpc_id = aws_vpc.cspm.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.cspm.id
  }
}
resource "aws_route_table_association" "tasks" {
  subnet_id      = aws_subnet.tasks.id
  route_table_id = aws_route_table.tasks.id
}
resource "aws_security_group" "tasks" {
  name   = local.name
  vpc_id = aws_vpc.cspm.id
  # No inbound rules. Public IP exists only for the bounded task lifetime.
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # Self-managed Kubernetes APIs commonly use their standard secure port.
  egress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.cspm.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.tasks.id]
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    {
      Effect   = "Allow", Principal = "*", Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
      Resource = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*", aws_s3_bucket.ai_transport.arn, "${aws_s3_bucket.ai_transport.arn}/*", "arn:aws:s3:::prod-${var.region}-starport-layer-bucket/*"]
    },
    {
      Effect   = "Allow", Principal = "*", Action = ["s3:DeleteObject"],
      Resource = "${aws_s3_bucket.ai_transport.arn}/invocations/*"
    },
    {
      # Customer roles still control authorization. In-Region buckets are read
      # through this endpoint, so it must allow every S3 read the collector
      # issues (bucket configuration, sampled object ACLs and the object reads
      # of explicitly selected leak sources); other Regions bypass it anyway.
      Effect   = "Allow", Principal = "*",
      Action   = ["s3:ListAllMyBuckets", "s3:GetAccountPublicAccessBlock", "s3:GetBucketAcl", "s3:GetBucketLocation", "s3:GetBucketLogging", "s3:GetBucketPolicy", "s3:GetBucketPolicyStatus", "s3:GetBucketPublicAccessBlock", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration", "s3:GetBucketOwnershipControls", "s3:GetLifecycleConfiguration", "s3:GetBucketNotification", "s3:GetReplicationConfiguration", "s3:GetBucketObjectLockConfiguration", "s3:GetBucketTagging", "s3:GetBucketWebsite", "s3:ListBucket", "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAcl"],
      Resource = "*"
    }
  ] })
}
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.cspm.id
  service_name      = "com.amazonaws.${var.region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.tasks.id]
}
resource "aws_ecs_cluster" "cspm" { name = local.name }
resource "aws_cloudwatch_log_group" "tasks" {
  name              = "/ecs/${local.name}"
  retention_in_days = 7
}
