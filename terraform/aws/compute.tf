# Single k3s node. Cheaper than EKS (no control-plane fee) and shows
# the same Kubernetes skills. Flip create_node = false to stop paying for it.

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_security_group" "node" {
  #checkov:skip=CKV_AWS_382:Node must reach package mirrors, container registries and SSM endpoints over the internet.
  name        = "${var.project}-node"
  description = "k3s node: no inbound access, admin via SSM only"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "HTTPS out (SSM, registries, packages)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP out (some package mirrors)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS (VPC resolver)"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "NTP (Amazon Time Sync)"
    from_port   = 123
    to_port     = 123
    protocol    = "udp"
    cidr_blocks = ["169.254.169.123/32"]
  }
}

resource "aws_instance" "k3s" {
  #checkov:skip=CKV2_AWS_41:IAM instance profile is attached (false positive when count is used).
  count = var.create_node ? 1 : 0

  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.node.id]
  iam_instance_profile   = aws_iam_instance_profile.node.name
  monitoring             = true
  ebs_optimized          = true

  # IMDSv2 only: blocks the SSRF-to-credential-theft path.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/templates/k3s-userdata.sh.tftpl", {})

  tags = { Name = "${var.project}-k3s" }

  lifecycle {
    ignore_changes = [ami]
  }
}
