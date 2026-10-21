"""
Isolation Lambda - Component 2
Triggered by n8n (via AWS Lambda node or API Gateway) ONLY when LLM severity is high/critical
AND VirusTotal reputation confirms risk (or FIM critical overrides VT).

Action: Replace EC2's Security Groups with the QUARANTINE SG (created in Component 1).
Effect: instance loses all inbound/outbound (except DNS) in <1s, preserved for forensics
         (NOT terminated, NOT stopped - evidence preserved).

IAM for this Lambda (least privilege, see terraform in README):
  - ec2:ModifyInstanceAttribute, ec2:DescribeInstances ONLY on the tagged instance
  - logs:CreateLogGroup/Stream/PutLogEvents for its own log group
"""
import json, os, boto3
from datetime import datetime, timezone

ec2 = boto3.client("ec2")
QUARANTINE_SG = os.environ["QUARANTINE_SG_ID"]          # from Component 1 output
ALLOWED_INSTANCE = os.environ.get("MONITORED_INSTANCE_ID", "")  # if set, only this instance can be isolated
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

def handler(event, context):
    body = event if isinstance(event, dict) else json.loads(event.get("body") or "{}")
    if "body" in event and isinstance(event["body"], str):
        try: body = json.loads(event["body"])
        except Exception: pass

    instance_id = body.get("instance_id")
    reason = body.get("reason", "high_severity_alert")
    severity = body.get("severity", "unknown")
    source_ip = body.get("source_ip", "unknown")

    if not instance_id or not instance_id.startswith("i-"):
        return resp(400, {"ok": False, "error": "valid instance_id required"})
    if ALLOWED_INSTANCE and instance_id != ALLOWED_INSTANCE:
        return resp(403, {"ok": False, "error": "instance not in allowlist"})

    desc = ec2.describe_instances(InstanceIds=[instance_id])
    reservations = desc.get("Reservations", [])
    if not reservations:
        return resp(404, {"ok": False, "error": "instance not found"})
    original_sgs = [g["GroupId"] for g in reservations[0]["Instances"][0].get("SecurityGroups", [])]

    result = {
        "ok": True, "action": "isolate", "instance_id": instance_id,
        "original_security_groups": original_sgs,
        "quarantine_security_group": QUARANTINE_SG,
        "severity": severity, "source_ip": source_ip, "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(), "dry_run": DRY_RUN,
    }

    if not DRY_RUN:
        ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[QUARANTINE_SG])

    print(json.dumps(result))  # CloudWatch - forensic trail
    return resp(200, result)

def resp(code, body):
    return {"statusCode": code, "headers": {"Content-Type": "application/json"}, "body": json.dumps(body)}

# Rollback helper (manual, in README): re-apply original SGs from the result above
# aws ec2 modify-instance-attribute --instance-id i-xxx --groups sg-original
