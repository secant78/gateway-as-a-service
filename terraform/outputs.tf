# ============================================================
# Terraform Outputs — GaaS Infrastructure
# ============================================================
#
# PURPOSE:
#   Outputs are values that Terraform prints after `terraform apply` completes.
#   They serve two purposes:
#     1. Inform the operator of resource identifiers they need for next steps
#        (e.g., "configure APISIX to use this ALB DNS as the upstream host")
#     2. Allow downstream automation to read values programmatically:
#        terraform output -raw load_balancer_dns
#        → gaas-gateway-alb-1234567890.us-east-1.elb.amazonaws.com
#
# USAGE IN CI PIPELINE (05-gaas-pipeline.yml):
#   The terraform-apply job captures the ALB DNS and can pass it as an
#   environment variable to subsequent steps that configure APISIX:
#     LB_DNS=$(terraform output -raw load_balancer_dns)
#     apisix configure upstream --host $LB_DNS
# ============================================================

# The fully-qualified DNS name of the Application Load Balancer.
# This is the public hostname for all GaaS tenant API traffic.
#
# Format: <alb-name>-<random-id>.<region>.elb.amazonaws.com
# Example: gaas-gateway-alb-1234567890.us-east-1.elb.amazonaws.com
#
# HOW TO USE:
#   1. Create a CNAME DNS record: api.yourdomain.com → <this value>
#   2. Or configure APISIX's upstream host to this DNS name
#   3. Or point your API documentation to https://<this value>
output "load_balancer_dns" {
  description = "DNS name of the APISIX Application Load Balancer. Configure this as the APISIX upstream host."
  value       = aws_lb.gaas_gateway.dns_name
}

# The ARN (Amazon Resource Name) of the ALB.
# ARNs uniquely identify AWS resources and are used to:
#   - Associate AWS WAF (Web Application Firewall) with the ALB
#   - Configure CloudWatch alarms for ALB metrics
#   - Reference the ALB in IAM policies
output "load_balancer_arn" {
  description = "ARN of the ALB — used for ALB WAF association or access log configuration"
  value       = aws_lb.gaas_gateway.arn
}

# The ARN of the APISIX Target Group.
# Use this to:
#   - Register additional Minikube/EKS nodes as targets (scale out):
#     aws elbv2 register-targets --target-group-arn <arn> --targets Id=10.0.1.5,Port=30080
#   - Deregister a node during maintenance:
#     aws elbv2 deregister-targets --target-group-arn <arn> --targets Id=10.0.1.5
output "target_group_arn" {
  description = "ARN of the APISIX target group — used to register additional Minikube nodes"
  value       = aws_lb_target_group.apisix.arn
}

# The Security Group ID of the ALB.
# Use this to:
#   - Add an inbound rule to the Minikube/EC2 node's security group so the ALB
#     health checks can reach the NodePort:
#     aws ec2 authorize-security-group-ingress \
#       --group-id <node-sg-id> \
#       --protocol tcp \
#       --port 30080 \
#       --source-group <this value>
output "alb_security_group_id" {
  description = "Security group ID of the ALB — add to Minikube node's inbound rules to allow health checks"
  value       = aws_security_group.alb.id
}
