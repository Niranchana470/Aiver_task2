#!/bin/bash

# Cleanup script to remove vulnerable AWS resources created by setup_vulnerable_resources.sh
# WARNING: This will DELETE resources - make sure you have the correct timestamps/names

set -e  # Exit on error

echo "=========================================="
echo "Cleaning Up Vulnerable AWS Resources"
echo "=========================================="

# Get AWS account info
AWS_REGION=$(aws configure get region || echo "us-east-1")
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo "AWS Account: $AWS_ACCOUNT_ID"
echo "Region: $AWS_REGION"
echo ""
echo "⚠️  This will DELETE resources. Press Ctrl+C to cancel, or Enter to continue..."
read

# ============================================
# 1. Terminate EC2 Instance
# ============================================
echo "1. Terminating EC2 instances..."

INSTANCE_IDS=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=vulnerable-test-instance" \
  --query 'Reservations[].Instances[?State.Name!=`terminated`].[InstanceId]' \
  --output text)

if [ ! -z "$INSTANCE_IDS" ]; then
    aws ec2 terminate-instances --instance-ids $INSTANCE_IDS
    echo "  ✓ Terminated instances: $INSTANCE_IDS"
else
    echo "  ℹ No vulnerable instances found"
fi

# ============================================
# 2. Delete Lambda Function
# ============================================
echo ""
echo "2. Deleting Lambda functions..."

LAMBDA_FUNCTIONS=$(aws lambda list-functions --query 'Functions[?contains(FunctionName, `vulnerable`)].FunctionName' --output text)

for func in $LAMBDA_FUNCTIONS; do
    aws lambda delete-function --function-name $func
    echo "  ✓ Deleted Lambda function: $func"
done

# ============================================
# 3. Delete IAM Users and Policies
# ============================================
echo ""
echo "3. Deleting IAM users..."

# Delete access keys and policies first, then users
USERS=$(aws iam list-users --query 'Users[?contains(UserName, `vulnerable`)].UserName' --output text)

for user in $USERS; do
    echo "  Cleaning up user: $user"
    
    # Delete access keys
    ACCESS_KEYS=$(aws iam list-access-keys --user-name $user --query 'AccessKeyMetadata[].AccessKeyId' --output text)
    for key in $ACCESS_KEYS; do
        aws iam delete-access-key --user-name $user --access-key-id $key
        echo "    - Deleted access key: $key"
    done
    
    # Delete inline policies
    POLICIES=$(aws iam list-user-policies --user-name $user --query 'PolicyNames' --output text)
    for policy in $POLICIES; do
        aws iam delete-user-policy --user-name $user --policy-name $policy
        echo "    - Deleted policy: $policy"
    done
    
    # Delete user
    aws iam delete-user --user-name $user
    echo "  ✓ Deleted user: $user"
done

# Delete Lambda role
ROLE_NAME="vulnerable-lambda-role"
if aws iam get-role --role-name $ROLE_NAME 2>/dev/null; then
    # Detach policies first
    POLICIES=$(aws iam list-attached-role-policies --role-name $ROLE_NAME --query 'AttachedPolicies[].PolicyArn' --output text)
    for policy in $POLICIES; do
        aws iam detach-role-policy --role-name $ROLE_NAME --policy-arn $policy
        echo "    - Detached policy from role: $policy"
    done
    
    aws iam delete-role --role-name $ROLE_NAME
    echo "  ✓ Deleted role: $ROLE_NAME"
fi

# ============================================
# 4. Delete Security Groups
# ============================================
echo ""
echo "4. Deleting security groups..."

SG_IDS=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=vulnerable-*" \
  --query 'SecurityGroups[].GroupId' \
  --output text)

for sg in $SG_IDS; do
    # Delete all rules first
    INGRESS_RULES=$(aws ec2 describe-security-group-rules \
      --filters "Name=group-id,Values=$sg" --query 'SecurityRules[?IsEgress==`false`].GroupId' --output text)
    
    # Delete security group
    aws ec2 delete-security-group --group-id $sg
    echo "  ✓ Deleted security group: $sg"
done

# ============================================
# 5. Delete S3 Buckets
# ============================================
echo ""
echo "5. Deleting S3 buckets..."

BUCKETS=$(aws s3api list-buckets --query 'Buckets[?contains(Name, `vulnerable`)].Name' --output text)

for bucket in $BUCKETS; do
    echo "  Cleaning up bucket: $bucket"
    
    # Delete all objects first
    aws s3 rm s3://$bucket --recursive --force 2>/dev/null || true
    
    # Delete bucket
    aws s3api delete-bucket --bucket $bucket --region $AWS_REGION
    echo "  ✓ Deleted bucket: $bucket"
done

# ============================================
# 6. Delete KMS Keys
# ============================================
echo ""
echo "6. Deleting KMS keys..."

KEYS=$(aws kms list-keys --query 'Keys[].KeyId' --output text)

for key in $KEYS; do
    # Check if key has our tag or description
    METADATA=$(aws kms describe-key --key-id $key)
    if echo "$METADATA" | grep -q "Vulnerable"; then
        # Schedule key for deletion
        aws kms schedule-key-deletion --key-id $key --pending-window-in-days 7
        echo "  ✓ Scheduled KMS key for deletion: $key"
    fi
done

# ============================================
# 7. Reset Password Policy
# ============================================
echo ""
echo "7. Resetting password policy to secure defaults..."

aws iam update-account-password-policy \
  --minimum-password-length 12 \
  --require-symbols true \
  --require-numbers true \
  --require-uppercase-characters true \
  --require-lowercase-characters true \
  --allow-users-to-change-password true \
  --max-password-age 90 \
  --password-reuse-prevention 24

echo "  ✓ Reset password policy to secure defaults"

# ============================================
# 8. Delete RDS Subnet Group
# ============================================
echo ""
echo "8. Deleting RDS subnet groups..."

SUBNET_GROUPS=$(aws rds describe-db-subnet-groups --query 'DBSubnetGroups[?contains(DBSubnetGroupName, `vulnerable`)].DBSubnetGroupName' --output text)

for group in $SUBNET_GROUPS; do
    aws rds delete-db-subnet-group --db-subnet-group-name $group
    echo "  ✓ Deleted RDS subnet group: $group"
done

# ============================================
# Summary
# ============================================
echo ""
echo "=========================================="
echo "Cleanup Complete!"
echo "=========================================="
echo ""
echo "Note: KMS keys are scheduled for deletion and will be deleted after 7 days"
echo "      EC2 instances may take a few minutes to fully terminate"
echo ""
