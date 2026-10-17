output "github_plan_role_arn" {
  description = "Put this in the GitHub repo variable AWS_PLAN_ROLE_ARN."
  value       = aws_iam_role.github_plan.arn
}

output "node_instance_id" {
  value = try(aws_instance.k3s[0].id, null)
}

output "connect_command" {
  description = "Open a shell on the node without SSH or open ports."
  value       = try("aws ssm start-session --target ${aws_instance.k3s[0].id} --region ${var.aws_region}", "node not created")
}

output "flow_log_group" {
  value = aws_cloudwatch_log_group.flow_logs.name
}
