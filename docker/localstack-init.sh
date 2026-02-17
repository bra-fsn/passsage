#!/bin/bash
# LocalStack initialization script - runs when LocalStack is ready
# Creates the proxy-cache bucket with full access policy for xs3lerator integration

set -e

echo "Creating S3 bucket: proxy-cache"
awslocal s3 mb s3://proxy-cache

echo "Setting full access policy on proxy-cache bucket"
awslocal s3api put-bucket-policy --bucket proxy-cache --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "FullAccess",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::proxy-cache",
      "arn:aws:s3:::proxy-cache/*"
    ]
  }]
}'

echo "LocalStack S3 initialization complete"
