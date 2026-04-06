# ============================================================
# Terraform Configuration — GaaS Cloud Infrastructure
# ============================================================
#
# PURPOSE:
#   Provisions the AWS cloud resources that sit OUTSIDE the Kubernetes cluster:
#   specifically the Application Load Balancer (ALB) that provides a public
#   HTTPS endpoint for the APISIX gateway running inside Minikube.
#
# WHAT TERRAFORM MANAGES (AND WHAT IT DOESN'T):
#   ✓ AWS ALB (Application Load Balancer)
#   ✓ ALB Target Group pointing at APISIX NodePort
#   ✓ HTTPS Listener with ACM certificate
#   ✓ HTTP Listener with 301 redirect to HTTPS
#   ✓ Security Group controlling inbound/outbound traffic to the ALB
#
#   ✗ Kubernetes resources (Deployments, Services, Helm releases)
#      → Managed by `helm install` and `kubectl apply` in the CI pipeline
#   ✗ Istio configuration (VirtualServices, PeerAuthentication)
#      → Managed by istioctl and kubectl in the CI pipeline
#
#   DESIGN REASON: Kubernetes resources change frequently during development.
#   If Terraform managed them, every `kubectl apply` would create state drift
#   and every `terraform plan` would try to revert the changes. Separating
#   "stable cloud infra" (Terraform) from "dynamic K8s config" (kubectl/helm)
#   keeps the Terraform state file small and prevents thrashing.
#
# BACKEND CONFIGURATION:
#   Terraform state is stored in the S3 bucket from the existing repo.
#   IMPORTANT: Update the bucket name if you fork this project.
#   You can override at init time:
#     terraform init -backend-config="bucket=YOUR_BUCKET_NAME"
#
# HOW TO RUN:
#   terraform init    # Download providers, configure backend
#   terraform plan    # Preview changes
#   terraform apply   # Create/update AWS resources
#   terraform destroy # Tear everything down
# ============================================================

terraform {
  # Minimum Terraform version — uses features from 1.7 (import blocks, etc.)
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      # ~> 5.0 means "any 5.x version" — allows patch upgrades but not major version bumps
      version = "~> 5.0"
    }
  }

  # Remote state backend: stores terraform.tfstate in S3 so the CI pipeline
  # and local developers all work from the same state.
  # encrypt=true: the state file is encrypted at rest using AWS SSE-S3.
  # use_lockfile=true: prevents concurrent terraform applies from corrupting state.
  backend "s3" {
    bucket       = "s3-primary-sean-0303"     # UPDATE THIS to your own bucket name
    key          = "gaas/terraform.tfstate"   # Path within the bucket (like a filename)
    region       = "us-east-1"
    encrypt      = true                       # Server-side encryption for the state file
    use_lockfile = true                       # Lock state during apply to prevent conflicts
  }
}

# AWS provider: authenticates to AWS using environment variables or OIDC.
# In the CI pipeline (05-gaas-pipeline.yml), AWS credentials are obtained via
# OIDC federated identity — no long-lived access keys stored in GitHub Secrets.
provider "aws" {
  region = var.aws_region

  # default_tags: these tags are automatically applied to ALL resources created by this provider.
  # This makes cost attribution, resource filtering, and compliance reporting easy.
  default_tags {
    tags = {
      Project     = "gaas"
      Environment = var.environment     # "staging" or "production"
      ManagedBy   = "terraform"         # Distinguishes Terraform-managed from manually created
    }
  }
}

# ============================================================
# Security Group: controls traffic to/from the ALB
# ============================================================
# A Security Group is AWS's virtual firewall. It controls:
#   - Ingress (inbound) rules: who can send traffic TO the ALB
#   - Egress (outbound) rules: where the ALB can send traffic
# Security Groups are stateful — return traffic is automatically allowed.
resource "aws_security_group" "alb" {
  name        = "gaas-alb-sg"
  description = "Security group for GaaS APISIX Application Load Balancer"
  vpc_id      = var.vpc_id   # The VPC where the ALB lives

  # Allow inbound HTTPS (port 443) from anywhere.
  # The internet must be able to reach the ALB on port 443 for the gateway to be useful.
  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # All IPv4 addresses
  }

  # Allow inbound HTTP (port 80) from anywhere — immediately redirected to HTTPS.
  # Without this, browsers typing http://gaas.internal would get a connection refused.
  ingress {
    description = "HTTP redirect to HTTPS"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow outbound traffic from the ALB to the APISIX NodePort on the Minikube/EC2 node.
  # The ALB forwards decrypted HTTP to APISIX — it needs to reach the node's NodePort.
  # Restricting to RFC 1918 private ranges means the ALB cannot forward to external IPs.
  egress {
    description = "Allow ALB to reach APISIX NodePort on Minikube node"
    from_port   = var.apisix_node_port   # e.g., 30080
    to_port     = var.apisix_node_port
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }
}

# ============================================================
# Application Load Balancer
# ============================================================
# The ALB is the public internet entry point for all GaaS tenant APIs.
# It performs TLS termination (decrypts HTTPS) and forwards plain HTTP
# to APISIX's NodePort (30080) on the Minikube node.
#
# Request flow:
#   Internet → ALB:443 (HTTPS) → ALB decrypts → APISIX:30080 (HTTP) → tenant service
resource "aws_lb" "gaas_gateway" {
  name               = "gaas-gateway-alb"
  internal           = false                    # External (internet-facing)
  load_balancer_type = "application"            # ALB (Layer 7, HTTP-aware) vs NLB (Layer 4, TCP)
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids    # Must span 2+ AZs for ALB requirement

  # Deletion protection: prevents accidental `terraform destroy` on production.
  # Dynamic expression: only enabled if environment == "production".
  enable_deletion_protection = var.environment == "production"

  # ALB access logs: every request (including rejected ones) is logged to S3.
  # Useful for debugging, security auditing, and SLA measurement.
  access_logs {
    bucket  = "s3-primary-sean-0303"   # UPDATE: use a dedicated log bucket in production
    prefix  = "gaas-alb-logs"          # S3 prefix/folder for these logs
    enabled = true
  }
}

# ============================================================
# Target Group: tells the ALB where to forward traffic
# ============================================================
# A Target Group is a pool of backend servers.
# The ALB HTTPS listener (below) forwards requests to this Target Group.
# The Target Group then load-balances across registered targets (Minikube node IPs).
resource "aws_lb_target_group" "apisix" {
  name        = "gaas-apisix-tg"
  port        = var.apisix_node_port   # The NodePort where APISIX listens (30080)
  protocol    = "HTTP"                 # Plain HTTP from ALB to APISIX (TLS terminated at ALB)
  target_type = "ip"                   # Register targets by IP address (vs instance ID)
  vpc_id      = var.vpc_id

  # Health check: the ALB periodically checks if APISIX is healthy.
  # If the health check fails, the ALB stops sending traffic to that target.
  health_check {
    enabled             = true
    path                = "/apisix/status"   # APISIX's built-in status endpoint
    port                = "traffic-port"      # Use the same port as the target (30080)
    protocol            = "HTTP"
    healthy_threshold   = 2      # 2 consecutive successes → mark healthy
    unhealthy_threshold = 3      # 3 consecutive failures → mark unhealthy
    timeout             = 5      # seconds to wait for a response
    interval            = 30     # seconds between health checks
    matcher             = "200"  # Only HTTP 200 counts as healthy
  }
}

# Register the Minikube node's IP address as a target in the Target Group.
# The ALB will forward all traffic to this IP on port 30080 (APISIX NodePort).
# In production with multiple nodes: add one aws_lb_target_group_attachment per node.
resource "aws_lb_target_group_attachment" "minikube_node" {
  target_group_arn = aws_lb_target_group.apisix.arn
  target_id        = var.minikube_node_ip   # IP from `minikube ip` or EC2 instance IP
  port             = var.apisix_node_port
}

# ============================================================
# HTTPS Listener (port 443)
# ============================================================
# The HTTPS listener is the main production entry point.
# It terminates TLS using the ACM certificate and forwards decrypted
# HTTP traffic to the APISIX Target Group.
#
# TLS policy "ELBSecurityPolicy-TLS13-1-2-2021-06" enforces:
#   - TLS 1.2 and TLS 1.3 only (TLS 1.0 and 1.1 are disabled)
#   - Modern cipher suites only (no RC4, DES, or export ciphers)
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.gaas_gateway.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"   # Enforces TLS 1.2+
  certificate_arn   = var.acm_cert_arn   # ACM certificate ARN for your domain

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.apisix.arn
  }
}

# ============================================================
# HTTP Listener (port 80) — Redirects to HTTPS
# ============================================================
# Any request on port 80 (plain HTTP) is permanently redirected to HTTPS.
# HTTP_301 tells browsers to update their bookmarks — future requests go directly to HTTPS.
# This ensures no plaintext API traffic reaches APISIX.
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.gaas_gateway.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"   # Permanent redirect — browsers cache this
    }
  }
}
