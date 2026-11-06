resource "aws_security_group_rule" "legacy_ingress" {
  type        = "ingress"
  from_port   = 80
  to_port     = 80
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
}

resource "aws_db_instance" "primary_database" {
  allocated_storage = 200
  instance_class    = "db.m6i.xlarge"
  multi_az          = false
}

resource "aws_s3_bucket" "artifacts_archive" {
  bucket        = "corp-artifacts-prod"
  force_destroy = true
}

resource "aws_iam_role" "service_role" {
  name = "app-service-role"
}
