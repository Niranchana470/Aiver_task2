#!/bin/bash

# Setup script to create intentionally vulnerable AWS resources for testing
# This script creates resources with common security misconfigurations
# WARNING: Use only in test/dev accounts - DO NOT use in production

set +e  # Don't exit on error - continue with remaining resources

echo "=========================================="
echo "Setting up Vulnerable AWS Resources"
echo "=========================================="

# Get AWS account info
AWS_REGION=$(aws configure get region || echo "us-east-1")
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
TIMESTAMP=$(date +%s)

echo "AWS Account: $AWS_ACCOUNT_ID"
echo "Region: $AWS_REGION"
echo ""

# ============================================
# 1. S3 Buckets with Security Issues
# ============================================
echo "1. Creating vulnerable S3 buckets..."

# S3 Bucket 1: Public ACL (Critical vulnerability)
BUCKET1="vulnerable-public-acl-${TIMESTAMP}"
aws s3api create-bucket --bucket $BUCKET1 --region $AWS_REGION 2>/dev/null || echo "  (Bucket may already exist)"
# Make bucket public using simplified approach
aws s3api put-bucket-acl --bucket $BUCKET1 --acl public-read 2>/dev/null || true
echo "  ✓ Created: $BUCKET1 (Public ACL - CRITICAL)"

# S3 Bucket 2: No encryption (High vulnerability)
BUCKET2="vulnerable-no-encryption-${TIMESTAMP}"
aws s3api create-bucket --bucket $BUCKET2 --region $AWS_REGION 2>/dev/null || echo "  (Bucket may already exist)"
echo "  ✓ Created: $BUCKET2 (No encryption - HIGH)"

# S3 Bucket 3: No versioning (Medium vulnerability)
BUCKET3="vulnerable-no-versioning-${TIMESTAMP}"
aws s3api create-bucket --bucket $BUCKET3 --region $AWS_REGION 2>/dev/null || echo "  (Bucket may already exist)"
echo "  ✓ Created: $BUCKET3 (No versioning - MEDIUM)"

# S3 Bucket 4: Public access block disabled (High vulnerability)
BUCKET4="vulnerable-public-access-${TIMESTAMP}"
aws s3api create-bucket --bucket $BUCKET4 --region $AWS_REGION 2>/dev/null || echo "  (Bucket may already exist)"
aws s3api delete-public-access-block --bucket $BUCKET4 2>/dev/null || true
echo "  ✓ Created: $BUCKET4 (Public access block disabled - HIGH)"

# ============================================
# 2. IAM Security Issues
# ============================================
echo ""
echo "2. Creating IAM users with security issues..."

# IAM User 1: No MFA (High vulnerability)
USER1="vulnerable-user-no-mfa"
aws iam create-user --user-name $USER1 2>/dev/null || echo "  (User may already exist)"
# Create access key for this user
aws iam create-access-key --user-name $USER1 2>/dev/null || echo "  (Access key may already exist)"
echo "  ✓ Created: $USER1 (No MFA - HIGH)"

# IAM User 2: With inline policy containing wildcard (Critical vulnerability)
USER2="vulnerable-user-wildcard-policy"
aws iam create-user --user-name $USER2 2>/dev/null || echo "  (User may already exist)"
aws iam put-user-policy --user-name $USER2 --policy-name "WildcardPolicy" --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}' 2>/dev/null || echo "  (Policy may already exist)"
echo "  ✓ Created: $USER2 (Wildcard policy - CRITICAL)"

# ============================================
# 3. Security Group with Open Ports
# ============================================
echo ""
echo "3. Creating vulnerable security groups..."

# Security Group 1: Open SSH to world (Critical vulnerability)
SG1_NAME="vulnerable-ssh-worldwide-${TIMESTAMP}"
SG1_ID=$(aws ec2 create-security-group --group-name $SG1_NAME --description "Security group with open SSH to 0.0.0.0/0" --query 'GroupId' --output text 2>/dev/null)
if [ ! -z "$SG1_ID" ]; then
    aws ec2 authorize-security-group-ingress --group-id $SG1_ID --protocol tcp --port 22 --cidr 0.0.0.0/0 2>/dev/null || true
    echo "  ✓ Created: $SG1_ID (Open SSH to 0.0.0.0/0 - CRITICAL)"
else
    echo "  (Security group may already exist)"
    SG1_ID=$(aws ec2 describe-security-groups --group-names "$SG1_NAME" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "")
fi

# Security Group 2: Open HTTP/HTTPS to world (High vulnerability)
SG2_NAME="vulnerable-http-worldwide-${TIMESTAMP}"
SG2_ID=$(aws ec2 create-security-group --group-name $SG2_NAME --description "Security group with open HTTP/HTTPS to 0.0.0.0/0" --query 'GroupId' --output text 2>/dev/null)
if [ ! -z "$SG2_ID" ]; then
    aws ec2 authorize-security-group-ingress --group-id $SG2_ID --protocol tcp --port 80 --cidr 0.0.0.0/0 2>/dev/null || true
    aws ec2 authorize-security-group-ingress --group-id $SG2_ID --protocol tcp --port 443 --cidr 0.0.0.0/0 2>/dev/null || true
    echo "  ✓ Created: $SG2_ID (Open HTTP/HTTPS to 0.0.0.0/0 - HIGH)"
else
    echo "  (Security group may already exist)"
    SG2_ID=$(aws ec2 describe-security-groups --group-names "$SG2_NAME" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "")
fi

# Security Group 3: Open RDP to world (Critical vulnerability)
SG3_NAME="vulnerable-rdp-worldwide-${TIMESTAMP}"
SG3_ID=$(aws ec2 create-security-group --group-name $SG3_NAME --description "Security group with open RDP to 0.0.0.0/0" --query 'GroupId' --output text 2>/dev/null)
if [ ! -z "$SG3_ID" ]; then
    aws ec2 authorize-security-group-ingress --group-id $SG3_ID --protocol tcp --port 3389 --cidr 0.0.0.0/0 2>/dev/null || true
    echo "  ✓ Created: $SG3_ID (Open RDP to 0.0.0.0/0 - CRITICAL)"
else
    echo "  (Security group may already exist)"
    SG3_ID=$(aws ec2 describe-security-groups --group-names "$SG3_NAME" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "")
fi

# ============================================
# 4. EC2 Instance with Security Issues
# ============================================
echo ""
echo "4. Creating vulnerable EC2 instance..."

# Find a suitable AMI
AMI_ID=$(aws ec2 describe-images --owners amazon --filters "Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2" "Name=state,Values=available" --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' --output text 2>/dev/null)

if [ ! -z "$AMI_ID" ] && [ ! -z "$SG1_ID" ]; then
    # Create EC2 instance with unencrypted EBS volume and no IMDSv2
    INSTANCE_ID=$(aws ec2 run-instances \
      --image-id $AMI_ID \
      --instance-type t2.micro \
      --security-group-ids $SG1_ID \
      --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=vulnerable-test-instance}]' \
      --metadata-options "HttpEndpoint=enabled,HttpTokens=optional" \
      --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":8,"DeleteOnTermination":true,"VolumeType":"gp2","Encrypted":false}}]' \
      --query 'Instances[0].InstanceId' \
      --output text 2>/dev/null)
    
    if [ ! -z "$INSTANCE_ID" ]; then
        echo "  ✓ Created: $INSTANCE_ID (Unencrypted EBS + IMDSv2 optional - HIGH)"
    else
        echo "  (Failed to create EC2 instance)"
        INSTANCE_ID="i-notcreated"
    fi
else
    echo "  (Could not find suitable AMI or security group)"
    INSTANCE_ID="i-notcreated"
fi

# ============================================
# 5. Weak Password Policy
# ============================================
echo ""
echo "5. Setting weak password policy..."

# Set weak password policy (no requirements)
aws iam update-account-password-policy \
  --minimum-password-length 8 \
  --allow-users-to-change-password \
  --max-password-age 0 \
  --password-reuse-prevention 0 2>/dev/null || echo "  (Could not update password policy)"

echo "  ✓ Set weak password policy (MEDIUM)"

# ============================================
# 6. KMS Key with Weak Permissions
# ============================================
echo ""
echo "6. Creating KMS key with weak permissions..."

# Create KMS key with overly permissive key policy
KMS_KEY_ID=$(aws kms create-key --description 'Vulnerable KMS key with weak policy' --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::'$AWS_ACCOUNT_ID':root"
      },
      "Action": "kms:*",
      "Resource": "*"
    }
  ]
}' --query 'KeyMetadata.KeyId' --output text 2>/dev/null)

if [ ! -z "$KMS_KEY_ID" ]; then
    echo "  ✓ Created: $KMS_KEY_ID (Overly permissive policy - MEDIUM)"
else
    echo "  (Could not create KMS key)"
    KMS_KEY_ID="key-notcreated"
fi

# ============================================
# 7. Lambda Function with Admin Privileges
# ============================================
echo ""
echo "7. Creating Lambda function with excessive permissions..."

# Create IAM role for Lambda with admin privileges
ROLE_NAME="vulnerable-lambda-role"
aws iam create-role --role-name $ROLE_NAME --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}' 2>/dev/null || echo "  (Role may already exist)"

# Attach admin policy to the role (using standard AWS policy)
aws iam attach-role-policy --role-name $ROLE_NAME --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>/dev/null || true

# Create simple Lambda deployment package
mkdir -p /tmp/lambda
cat > /tmp/lambda/index.js << 'EOF'
exports.handler = async (event) => {
  return { statusCode: 200, body: "Hello from vulnerable Lambda" };
};
EOF

cd /tmp/lambda && zip -r /tmp/lambda_function.zip . && cd - > /dev/null

# Create Lambda function
LAMBDA_EXISTS=$(aws lambda get-function --function-name vulnerable-lambda-function 2>/dev/null)
if [ -z "$LAMBDA_EXISTS" ]; then
    aws lambda create-function \
      --function-name vulnerable-lambda-function \
      --runtime nodejs18.x \
      --role arn:aws:iam::$AWS_ACCOUNT_ID:role/$ROLE_NAME \
      --handler index.handler \
      --zip-file fileb:///tmp/lambda_function.zip \
      --description "Lambda with admin privileges" 2>/dev/null && echo "  ✓ Created: vulnerable-lambda-function (Admin privileges - CRITICAL)" || echo "  (Could not create Lambda function)"
else
    echo "  ✓ Lambda function already exists: vulnerable-lambda-function"
fi

# ============================================
# 8. CloudTrail Not Enabled
# ============================================
echo ""
echo "8. Checking CloudTrail status..."

# Check if any trails exist
TRAILS=$(aws cloudtrail describe-trails --query 'trailList' --output text 2>/dev/null)
if [ -z "$TRAILS" ]; then
    echo "  ⚠ No CloudTrail trails found (logging disabled - MEDIUM)"
else
    echo "  ℹ CloudTrail is enabled"
fi

# ============================================
# Summary
# ============================================
echo ""
echo "=========================================="
echo "Vulnerable Resources Created"
echo "=========================================="
echo ""
echo "S3 Buckets:"
echo "  - s3://$BUCKET1 (Public ACL - CRITICAL)"
echo "  - s3://$BUCKET2 (No encryption - HIGH)"
echo "  - s3://$BUCKET3 (No versioning - MEDIUM)"
echo "  - s3://$BUCKET4 (Public access disabled - HIGH)"
echo ""
echo "IAM Users:"
echo "  - $USER1 (No MFA - HIGH)"
echo "  - $USER2 (Wildcard policy - CRITICAL)"
echo ""
echo "Security Groups:"
echo "  - $SG1_ID (Open SSH - CRITICAL)"
echo "  - $SG2_ID (Open HTTP/HTTPS - HIGH)"
echo "  - $SG3_ID (Open RDP - CRITICAL)"
echo ""
echo "EC2 Instance:"
echo "  - $INSTANCE_ID (Unencrypted EBS, no IMDSv2 - HIGH)"
echo ""
echo "KMS Key:"
echo "  - $KMS_KEY_ID (Weak policy - MEDIUM)"
echo ""
echo "Lambda Function:"
echo "  - vulnerable-lambda-function (Admin privileges - CRITICAL)"
echo ""
echo "Password Policy: Weak (MEDIUM)"
echo ""
echo "=========================================="
echo "Ready to test security agent!"
echo "=========================================="
echo ""
echo "To scan these resources, run:"
echo "  python main_agentic.py"
echo ""
echo "To clean up these resources:"
echo "  bash cleanup_vulnerable_resources.sh"
