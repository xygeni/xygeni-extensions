resource "aws_s3_bucket" "good_0" {
  bucket = "good_0"
  acl    = "private" # deprecated, but OK
}

resource "aws_s3_bucket" "good_1" {
  bucket = "good_1"
}

resource "aws_s3_bucket_acl" "example_bucket_acl_good" {
  bucket = aws_s3_bucket.good_1.id
  acl    = "private"
}

resource "aws_s3_bucket" "bad_0" {
  bucket = "bad_0"
  acl    = "public-read-write" # deprecated, too permissive
}


resource "aws_s3_bucket" "website" {
  bucket = "website"
}

resource "aws_s3_bucket_acl" "website_acl" {
  bucket = aws_s3_bucket.website.id
  acl    = "website" # FLAW
}
