# Vulnerable: open 0.0.0.0/0 SSH ingress (security-group check) + S3 bucket
# with no encryption/public-access-block configured (AVD-AWS-0088 / AVD-AWS-0086).
resource "aws_security_group" "bad_sg" {
  name = "open-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "bad_bucket" {
  bucket = "my-insecure-bucket-example"
}
