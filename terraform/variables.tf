# ============================================================
# Terraform Input Variables — GaaS Infrastructure
# ============================================================
#
# PURPOSE:
#   Defines all configurable inputs for the Terraform configuration in main.tf.
#   Variables allow the same Terraform code to be used across different environments
#   (staging, production) and by different team members with different AWS accounts.
#
# HOW TO PROVIDE VALUES:
#   Option 1: Command-line flags
#     terraform plan -var="minikube_node_ip=10.0.0.5"
#
#   Option 2: .tfvars file (NOT committed to git — add to .gitignore)
#     Create gaas.tfvars:
#       minikube_node_ip = "10.0.0.5"
#       acm_cert_arn     = "arn:aws:acm:..."
#     Then: terraform plan -var-file=gaas.tfvars
#
#   Option 3: Environment variables (used in CI)
#     TF_VAR_minikube_node_ip=10.0.0.5 terraform plan
#
# VALIDATION BLOCKS:
#   Terraform validates inputs BEFORE running any plan.
#   If a variable fails validation, terraform exits immediately with the error message.
#   This prevents misconfigured values from reaching AWS APIs.
# ============================================================

# The AWS region where ALL resources in main.tf are created.
# All resources (ALB, security group, target group) must be in the same region.
variable "aws_region" {
  type        = string
  description = "AWS region for the load balancer (e.g., us-east-1)"
  default     = "us-east-1"   # Default to us-east-1 to match the existing repo's S3 buckets
}

# Controls which environment-specific behaviors apply (e.g., deletion protection).
# Only "staging" and "production" are valid — the validation block enforces this.
variable "environment" {
  type        = string
  description = "Deployment environment tag applied to all resources"
  default     = "staging"

  validation {
    # contains() checks if the value is in the allowed list.
    # Prevents typos like "prod" or "dev" from slipping through.
    condition     = contains(["staging", "production"], var.environment)
    error_message = "environment must be 'staging' or 'production'"
  }
}

# The IP address of the node running Minikube (or an EKS worker node).
# The ALB Target Group forwards traffic to this IP on the APISIX NodePort.
#
# Get this value:
#   On Minikube: minikube ip
#   On EC2:      aws ec2 describe-instances --query "Reservations[0].Instances[0].PrivateIpAddress"
#
# No default — this MUST be provided. Failing to provide it causes terraform plan to fail.
variable "minikube_node_ip" {
  type        = string
  description = <<-EOT
    The IP address of the Minikube node (output of `minikube ip`).
    The ALB target group points at this IP on the APISIX NodePort.
    In a cloud-hosted Minikube-on-EC2 setup, this is the EC2 instance's
    private IP. For EKS, this would be a worker node IP instead.
  EOT
}

# The Kubernetes NodePort that APISIX listens on.
# MUST match the value in apisix-values.yaml gateway.http.nodePort (default: 30080).
# If these drift, the ALB health checks will fail and no traffic will reach APISIX.
variable "apisix_node_port" {
  type        = number
  description = "The NodePort on which APISIX listens (must match apisix-values.yaml gateway.http.nodePort)"
  default     = 30080

  validation {
    # Kubernetes NodePorts must be in the range 30000–32767 by default.
    # Ports outside this range are not valid NodePort values and Kubernetes
    # will reject the Service manifest.
    condition     = var.apisix_node_port >= 30000 && var.apisix_node_port <= 32767
    error_message = "Kubernetes NodePort must be in range 30000-32767"
  }
}

# The Amazon Resource Name (ARN) of an ACM (AWS Certificate Manager) certificate.
# This is used by the ALB HTTPS listener for TLS termination.
#
# How to create an ACM certificate:
#   1. Go to AWS Console → Certificate Manager → Request certificate
#   2. Enter your domain (e.g., gaas.yourdomain.com)
#   3. Choose DNS validation
#   4. Copy the ARN once issued: arn:aws:acm:us-east-1:123456789:certificate/abc-123
#
# sensitive=false because ARNs are not secret (they're visible in AWS console).
# The certificate itself is managed by ACM — we never handle the private key.
variable "acm_cert_arn" {
  type        = string
  description = "ARN of the ACM certificate for HTTPS on the ALB listener"
  sensitive   = false
}

# The VPC ID where the ALB and security group are created.
# The Minikube node (or EKS cluster) must also be in this VPC for routing to work.
#
# Get this value:
#   aws ec2 describe-vpcs --query "Vpcs[?IsDefault==\`true\`].VpcId" --output text
variable "vpc_id" {
  type        = string
  description = "VPC ID where the ALB will be created"
}

# At least 2 subnets in different Availability Zones (AZs) are required by AWS
# for an Application Load Balancer. This ensures the ALB is highly available —
# if one AZ has an outage, the ALB keeps working in the other AZ.
#
# The subnets must be in the same VPC as var.vpc_id.
# Use PUBLIC subnets (with internet gateway route) for an internet-facing ALB.
#
# Get subnet IDs:
#   aws ec2 describe-subnets --filter Name=vpc-id,Values=<vpc-id> \
#     --query "Subnets[*].[SubnetId,AvailabilityZone,MapPublicIpOnLaunch]"
variable "public_subnet_ids" {
  type        = list(string)
  description = "List of public subnet IDs for the ALB (minimum 2 for multi-AZ)"

  validation {
    # AWS requires at least 2 subnets in different AZs for ALB.
    # Providing only 1 subnet will fail at AWS API level with an unclear error.
    # This validation gives a much clearer message upfront.
    condition     = length(var.public_subnet_ids) >= 2
    error_message = "ALB requires at least 2 subnets in different Availability Zones"
  }
}
