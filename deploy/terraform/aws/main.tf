# PRAXIS core on AWS: RDS Postgres, Secrets Manager, S3 for artifacts, and the
# API and dashboard on ECS Fargate behind an HTTPS load balancer.
# This is Connect mode: bring your own SIEM. Agents and CD run elsewhere.

locals {
  tags = { Application = "praxis", ManagedBy = "terraform" }
}

data "aws_region" "current" {}

# ---- secrets -----------------------------------------------------------------
resource "random_password" "db" {
  length  = 32
  special = false
}

resource "random_password" "api_token" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "praxis" {
  name_prefix = "${var.name}-"
  tags        = local.tags
}

resource "aws_secretsmanager_secret_version" "praxis" {
  secret_id = aws_secretsmanager_secret.praxis.id
  secret_string = jsonencode({
    api_token    = random_password.api_token.result
    database_url = "postgresql://praxis:${random_password.db.result}@${aws_db_instance.praxis.address}:5432/praxis"
  })
}

# ---- network -----------------------------------------------------------------
resource "aws_security_group" "alb" {
  name_prefix = "${var.name}-alb-"
  vpc_id      = var.vpc_id
  tags        = local.tags

  ingress {
    description = "HTTPS from allowed networks"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "services" {
  name_prefix = "${var.name}-svc-"
  vpc_id      = var.vpc_id
  tags        = local.tags

  ingress {
    description     = "Dashboard from the load balancer"
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  ingress {
    description = "API from the dashboard"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    self        = true
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name_prefix = "${var.name}-db-"
  vpc_id      = var.vpc_id
  tags        = local.tags

  ingress {
    description     = "Postgres from the services"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.services.id]
  }
}

# ---- data --------------------------------------------------------------------
resource "aws_db_subnet_group" "praxis" {
  name_prefix = "${var.name}-"
  subnet_ids  = var.private_subnet_ids
  tags        = local.tags
}

resource "aws_db_instance" "praxis" {
  identifier_prefix         = "${var.name}-"
  engine                    = "postgres"
  engine_version            = "16"
  instance_class            = var.db_instance_class
  allocated_storage         = 20
  max_allocated_storage     = 100
  storage_encrypted         = true
  db_name                   = "praxis"
  username                  = "praxis"
  password                  = random_password.db.result
  db_subnet_group_name      = aws_db_subnet_group.praxis.name
  vpc_security_group_ids    = [aws_security_group.db.id]
  backup_retention_period   = 7
  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name}-final"
  tags                      = local.tags
}

resource "aws_s3_bucket" "artifacts" {
  bucket_prefix = "${var.name}-artifacts-"
  tags          = local.tags
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

# ---- compute -----------------------------------------------------------------
resource "aws_ecs_cluster" "praxis" {
  name = var.name
  tags = local.tags
}

resource "aws_cloudwatch_log_group" "praxis" {
  name              = "/ecs/${var.name}"
  retention_in_days = 30
  tags              = local.tags
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name_prefix        = "${var.name}-exec-"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "read_secret" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.praxis.arn]
  }
}

resource "aws_iam_role_policy" "read_secret" {
  name_prefix = "read-secret-"
  role        = aws_iam_role.execution.id
  policy      = data.aws_iam_policy_document.read_secret.json
}

resource "aws_service_discovery_http_namespace" "praxis" {
  name = var.name
  tags = local.tags
}

locals {
  log = {
    logDriver = "awslogs"
    options = {
      awslogs-group         = aws_cloudwatch_log_group.praxis.name
      awslogs-region        = data.aws_region.current.region
      awslogs-stream-prefix = "praxis"
    }
  }
  secret = aws_secretsmanager_secret.praxis.arn
}

resource "aws_ecs_task_definition" "api" {
  family                   = "${var.name}-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn
  tags                     = local.tags
  container_definitions = jsonencode([{
    name             = "api"
    image            = "${var.image_registry}/praxis-api:${var.image_tag}"
    essential        = true
    portMappings     = [{ name = "api", containerPort = 8000 }]
    logConfiguration = local.log
    secrets = [
      { name = "PRAXIS_DATABASE_URL", valueFrom = "${local.secret}:database_url::" },
      { name = "PRAXIS_API_TOKEN", valueFrom = "${local.secret}:api_token::" },
    ]
  }])
}

resource "aws_ecs_task_definition" "web" {
  family                   = "${var.name}-web"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn
  tags                     = local.tags
  container_definitions = jsonencode([{
    name             = "web"
    image            = "${var.image_registry}/praxis-web:${var.image_tag}"
    essential        = true
    portMappings     = [{ name = "web", containerPort = 3000 }]
    logConfiguration = local.log
    environment      = [{ name = "PRAXIS_API_URL", value = "http://api:8000" }]
    secrets          = [{ name = "PRAXIS_API_TOKEN", valueFrom = "${local.secret}:api_token::" }]
  }])
}

resource "aws_ecs_service" "api" {
  name            = "api"
  cluster         = aws_ecs_cluster.praxis.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  tags            = local.tags
  depends_on      = [aws_secretsmanager_secret_version.praxis]

  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [aws_security_group.services.id]
  }
  service_connect_configuration {
    enabled   = true
    namespace = aws_service_discovery_http_namespace.praxis.arn
    service {
      port_name = "api"
      client_alias {
        dns_name = "api"
        port     = 8000
      }
    }
  }
}

resource "aws_ecs_service" "web" {
  name            = "web"
  cluster         = aws_ecs_cluster.praxis.id
  task_definition = aws_ecs_task_definition.web.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  tags            = local.tags
  depends_on      = [aws_lb_listener.https]

  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [aws_security_group.services.id]
  }
  service_connect_configuration {
    enabled   = true
    namespace = aws_service_discovery_http_namespace.praxis.arn
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.web.arn
    container_name   = "web"
    container_port   = 3000
  }
}

# ---- load balancer -------------------------------------------------------------
resource "aws_lb" "praxis" {
  name_prefix        = "prx-"
  load_balancer_type = "application"
  subnets            = var.public_subnet_ids
  security_groups    = [aws_security_group.alb.id]
  tags               = local.tags
}

resource "aws_lb_target_group" "web" {
  name_prefix = "prx-"
  port        = 3000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id
  tags        = local.tags
  health_check {
    path    = "/"
    matcher = "200"
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.praxis.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}
