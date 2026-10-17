variable "aws_region" {
  description = "AWS region. us-east-2 (Ohio) is close to Kansas City."
  type        = string
  default     = "us-east-2"
}

variable "project" {
  description = "Name prefix for all resources."
  type        = string
  default     = "secure-platform"
}

variable "owner" {
  description = "Your name or handle, applied as a tag."
  type        = string
}

variable "github_repo" {
  description = "GitHub repo allowed to assume the CI role, as owner/name."
  type        = string
}

variable "budget_email" {
  description = "Email that receives budget alerts."
  type        = string
}

variable "monthly_budget_usd" {
  description = "Monthly spend limit that triggers alerts."
  type        = number
  default     = 20
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "public_subnet_cidr" {
  type    = string
  default = "10.20.1.0/24"
}

variable "instance_type" {
  description = "k3s node size. t3.medium is the smallest that runs the full stack comfortably."
  type        = string
  default     = "t3.medium"
}

variable "create_node" {
  description = "Set to false to tear down the EC2 node (the main cost) while keeping the network and IAM."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  type    = number
  default = 30
}
