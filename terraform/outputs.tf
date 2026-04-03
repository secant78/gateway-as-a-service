output "load_balancer_dns" {
  description = "DNS name of the APISIX Application Load Balancer. Configure this as the APISIX upstream host."
  value       = aws_lb.gaas_gateway.dns_name
}

output "load_balancer_arn" {
  description = "ARN of the ALB — used for ALB WAF association or access log configuration"
  value       = aws_lb.gaas_gateway.arn
}

output "target_group_arn" {
  description = "ARN of the APISIX target group — used to register additional Minikube nodes"
  value       = aws_lb_target_group.apisix.arn
}

output "alb_security_group_id" {
  description = "Security group ID of the ALB — add to Minikube node's inbound rules to allow health checks"
  value       = aws_security_group.alb.id
}
