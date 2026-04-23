#!/usr/bin/env python3
"""CloudTrail log parser for AWS security logs."""

import json
import re
from datetime import datetime
from typing import Optional


def parse_cloudtrail(line: str) -> Optional[dict]:
    """Parse CloudTrail JSON log line."""
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    
    event_time = data.get("eventTime", "")
    event_name = data.get("eventName", "")
    user_identity = data.get("userIdentity", {})
    user_name = user_identity.get("userName", "")
    user_type = user_identity.get("type", "")
    
    # Handle IAM identity
    if not user_name:
        arn = user_identity.get("arn", "")
        if "arn:aws:iam::" in arn:
            user_name = arn.split("/")[-1] if "/" in arn else arn
    
    # Source IP
    source_ip = data.get("sourceIPAddress", "")
    
    # AWS region
    aws_region = data.get("awsRegion", "")
    
    # Event category
    event_source = data.get("eventSource", "")
    event_category = categorize_event(event_name)
    
    # Request parameters
    request = data.get("requestParameters") or {}
    response = data.get("responseElements") or {}
    
    # Build message
    message = f"{event_name}"
    if request:
        if "userName" in request:
            message += f" user={request['userName']}"
        if "groupName" in request:
            message += f" group={request['groupName']}"
        if "policyName" in request:
            message += f" policy={request['policyName']}"
    if response:
        message += f" -> {list(response.keys())}"
    
    return {
        "timestamp": event_time,
        "host": f"aws:{aws_region}" if aws_region else "aws",
        "user": user_name or user_type or "unknown",
        "source_ip": source_ip,
        "destination_ip": "",
        "event_type": event_category,
        "process": event_source or "cloudtrail",
        "raw_message": message,
        "mitre_tactic": get_mitre_tactic(event_name),
    }


def categorize_event(event_name: str) -> str:
    """Categorize CloudTrail event."""
    category_map = {
        # Authentication
        "ConsoleLogin": "aws_login",
        "AssumeRole": "aws_role",
        "GetSessionToken": "aws_token",
        
        # IAM
        "CreateUser": "iam_create",
        "DeleteUser": "iam_delete",
        "AttachUserPolicy": "iam_policy",
        "DetachUserPolicy": "iam_policy",
        "CreateRole": "iam_role",
        "DeleteRole": "iam_role",
        "CreateGroup": "iam_group",
        
        # S3
        "PutBucketPolicy": "s3_policy",
        "GetBucketPolicy": "s3_policy",
        "DeleteBucket": "s3_delete",
        
        # EC2
        "RunInstances": "ec2_start",
        "TerminateInstances": "ec2_stop",
        "AuthorizeSecurityGroupIngress": "ec2_sg",
        
        # Lambdafunctions
        "CreateFunction": "lambda_create",
        "DeleteFunction": "lambda_delete",
        "UpdateFunctionCode": "lambda_update",
        
        # Secrets
        "PutSecretValue": "secrets_put",
        "GetSecretValue": "secrets_get",
    }
    return category_map.get(event_name, "aws_other")


MITRE_CLOUDTRAIL = {
    "CreateUser": "T1078",
    "DeleteUser": "T1078",
    "AttachUserPolicy": "T1098",
    "CreateRole": "T1098",
    "AssumeRole": "T1078",
    "RunInstances": "T1105",
    "DeleteFunction": "T1529",
    "PutSecretValue": "T1002",
    "GetSecretValue": "T1002",
}


def get_mitre_tactic(event_name: str) -> str:
    """Get MITRE tactic for CloudTrail event."""
    return MITRE_CLOUDTRAIL.get(event_name, "")


def detect_cloudtrail(line: str) -> bool:
    """Detect if line is CloudTrail JSON."""
    if line.startswith("{"):
        try:
            data = json.loads(line)
            return "eventVersion" in data and "eventTime" in data
        except json.JSONDecodeError:
            return False
    return False


if __name__ == "__main__":
    import sys
    for line in sys.stdin:
        line = line.strip()
        if line:
            record = parse_cloudtrail(line)
            if record:
                print(f"[{record['event_type']}] {record['user']} {record['timestamp']} {record['raw_message'][:50]}")