terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.69"
    }
  }

  # Start with local state. Once comfortable, move state to S3 with
  # native locking (use_lockfile = true) and server-side encryption.
  # backend "s3" {
  #   bucket       = "YOUR-tfstate-bucket"
  #   key          = "secure-platform/terraform.tfstate"
  #   region       = "us-east-2"
  #   encrypt      = true
  #   use_lockfile = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = var.project
      Owner     = var.owner
      ManagedBy = "terraform"
    }
  }
}
