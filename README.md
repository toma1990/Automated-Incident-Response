# Automated Incident Response System

A Python-based automated incident response system that monitors 
AWS GuardDuty for security findings and automatically responds 
to threats by isolating affected resources and preserving forensic 
evidence.

## What it does

When GuardDuty detects a high severity threat, the system:

- Opens a case with a unique ID and timestamp
- Captures the state of affected resources before taking action
- Isolates compromised EC2 instances by moving them to a 
  dedicated security group with no ingress or egress
- Preserves all evidence to S3 with AES-256 encryption
- Maintains a chain of custody log for every action taken
- Can be deployed as a Lambda function triggered automatically 
  by GuardDuty via EventBridge

## Why I built this

My background in digital forensics at Lincolnshire Police taught 
me that evidence integrity and chain of custody are as important 
as the response itself. Most automated IR tools focus on the 
containment side but treat evidence capture as an afterthought.

This system captures evidence first, before any remediation 
action is taken, and logs every step with timestamps in UTC - 
the same discipline you'd apply in a formal investigation.

## Tech used

- Python 3
- boto3 (AWS SDK)
- AWS GuardDuty
- AWS EC2 (isolation via security groups)
- AWS S3 (encrypted evidence storage)
- AWS Lambda (automated triggering)

## How to run it

Configure AWS CLI with appropriate permissions, update 
EVIDENCE_BUCKET with your S3 bucket name, then:

pip install boto3
python3 ir_responder.py

To deploy as Lambda, zip the file and upload to a Lambda function 
with an EventBridge trigger on GuardDuty findings.

## Chain of custody

Every case generates a JSON evidence package containing:

- Case ID and capture timestamp in UTC
- Full finding details from GuardDuty
- Resource state at time of detection
- Timestamped log of every action taken
- S3 location of preserved evidence

## What's next

Planning to add SNS notifications for on-call alerting, 
automated memory capture for compromised instances, and 
integration with the threat detection pipeline from my 
other project.
