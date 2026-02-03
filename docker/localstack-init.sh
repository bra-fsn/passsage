#!/bin/bash
# LocalStack initialization script - runs when LocalStack is ready
# Creates the proxy-cache bucket with public read policy

set -e

echo "Creating S3 bucket: proxy-cache"
awslocal s3 mb s3://proxy-cache

echo "Setting public read policy on proxy-cache bucket"
awslocal s3api put-bucket-policy --bucket proxy-cache --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicRead",
    "Effect": "Allow",
    "Principal": "*",
    "Action": ["s3:GetObject", "s3:HeadObject"],
    "Resource": "arn:aws:s3:::proxy-cache/*"
  }]
}'

echo "LocalStack S3 initialization complete"
