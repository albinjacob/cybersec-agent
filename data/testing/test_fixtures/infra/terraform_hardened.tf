resource "aws_security_group" "good_sg" {
  name = "restricted-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_s3_bucket" "good_bucket" {
  bucket = "my-secure-bucket-example"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "good_bucket_sse" {
  bucket = aws_s3_bucket.good_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "good_bucket_pab" {
  bucket                  = aws_s3_bucket.good_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
