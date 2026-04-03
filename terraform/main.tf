terraform {
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state — update the bucket name to match your environment.
  # The S3 bucket used here is the same one managed by the existing repo's
  # infrastructure (see setup_infrastructure.py).
  backend "s3" {
    bucket         = "s3-primary-sean-0303"
    key            = "gaas/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    use_lockfile   = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "gaas"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# ============================================================
# Security Group for the Application Load Balancer
# ============================================================
resource "aws_security_group" "alb" {
  name        = "gaas-alb-sg"
  description = "Security group for GaaS APISIX Application Load Balancer"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP redirect to HTTPS"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow ALB to reach APISIX NodePort on Minikube node"
    from_port   = var.apisix_node_port
    to_port     = var.apisix_node_port
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }
}

# ============================================================
# Application Load Balancer
# ============================================================
# DESIGN DECISION: Terraform manages only the cloud Load Balancer.
# Kubernetes resources (APISIX, Istio, tenant deployments) are
# managed by Helm and kubectl in the CI pipeline. This avoids
# Terraform state drift on fast-moving K8s objects and keeps the
# Terraform blast radius small (only the ALB + target group).
resource "aws_lb" "gaas_gateway" {
  name               = "gaas-gateway-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  enable_deletion_protection = var.environment == "production"

  access_logs {
    bucket  = "s3-primary-sean-0303"
    prefix  = "gaas-alb-logs"
    enabled = true
  }
}

# ============================================================
# Target Group → APISIX NodePort
# ============================================================
resource "aws_lb_target_group" "apisix" {
  name        = "gaas-apisix-tg"
  port        = var.apisix_node_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  health_check {
    enabled             = true
    path                = "/apisix/status"
    port                = "traffic-port"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }
}

# Register the Minikube node IP as a target
resource "aws_lb_target_group_attachment" "minikube_node" {
  target_group_arn = aws_lb_target_group.apisix.arn
  target_id        = var.minikube_node_ip
  port             = var.apisix_node_port
}

# ============================================================
# HTTPS Listener (port 443)
# ============================================================
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.gaas_gateway.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_cert_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.apisix.arn
  }
}

# ============================================================
# HTTP Listener (port 80) — Redirects to HTTPS
# ============================================================
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.gaas_gateway.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
