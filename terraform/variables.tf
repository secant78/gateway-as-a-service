variable "aws_region" {
  type        = string
  description = "AWS region for the load balancer (e.g., us-east-1)"
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Deployment environment tag applied to all resources"
  default     = "staging"

  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "environment must be 'staging' or 'production'"
  }
}

variable "minikube_node_ip" {
  type        = string
  description = <<-EOT
    The IP address of the Minikube node (output of `minikube ip`).
    The ALB target group points at this IP on the APISIX NodePort.
    In a cloud-hosted Minikube-on-EC2 setup, this is the EC2 instance's
    private IP. For EKS, this would be a worker node IP instead.
  EOT
}

variable "apisix_node_port" {
  type        = number
  description = "The NodePort on which APISIX listens (must match apisix-values.yaml gateway.http.nodePort)"
  default     = 30080

  validation {
    condition     = var.apisix_node_port >= 30000 && var.apisix_node_port <= 32767
    error_message = "Kubernetes NodePort must be in range 30000-32767"
  }
}

variable "acm_cert_arn" {
  type        = string
  description = "ARN of the ACM certificate for HTTPS on the ALB listener"
  sensitive   = false  # ARNs are not secret, but the cert itself is managed by ACM
}

variable "vpc_id" {
  type        = string
  description = "VPC ID where the ALB will be created"
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "List of public subnet IDs for the ALB (minimum 2 for multi-AZ)"

  validation {
    condition     = length(var.public_subnet_ids) >= 2
    error_message = "ALB requires at least 2 subnets in different Availability Zones"
  }
}
