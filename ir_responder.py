
import boto3
import json
import os
from datetime import datetime, timezone

# AWS clients
ec2 = boto3.client('ec2', region_name='eu-west-2')
iam = boto3.client('iam', region_name='eu-west-2')
s3 = boto3.client('s3', region_name='eu-west-2')
guardduty = boto3.client('guardduty', region_name='eu-west-2')

# S3 bucket to store forensic evidence - change this to your bucket name
EVIDENCE_BUCKET = 'ir-evidence-bucket-673778960564'

# Severity threshold - only respond to HIGH and CRITICAL findings
SEVERITY_THRESHOLD = 7.0

def get_timestamp():
    # Consistent timestamp format across all evidence - important for chain of custody
    return datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_UTC')

def capture_evidence(finding, instance_id=None):
    # Chain of custody starts here - every action is timestamped and logged
    timestamp = get_timestamp()
    case_id = f"IR-{timestamp}"
    
    evidence = {
        'CaseID': case_id,
        'CaptureTime': timestamp,
        'FindingID': finding.get('Id', 'unknown'),
        'FindingType': finding.get('Type', 'unknown'),
        'Severity': finding.get('Severity', 0),
        'Region': finding.get('Region', 'unknown'),
        'AccountID': finding.get('AccountId', 'unknown'),
        'Description': finding.get('Description', 'unknown'),
        'ChainOfCustody': [
            {
                'Action': 'Evidence capture initiated',
                'Timestamp': timestamp,
                'Method': 'Automated IR system',
                'Integrity': 'SHA-256 hash pending'
            }
        ]
    }
    
    # Capture affected resource details
    if instance_id:
        try:
            instance_info = ec2.describe_instances(InstanceIds=[instance_id])
            evidence['AffectedInstance'] = {
                'InstanceId': instance_id,
                'State': instance_info['Reservations'][0]['Instances'][0]['State']['Name'],
                'SecurityGroups': instance_info['Reservations'][0]['Instances'][0]['SecurityGroups'],
                'LaunchTime': str(instance_info['Reservations'][0]['Instances'][0]['LaunchTime'])
            }
            evidence['ChainOfCustody'].append({
                'Action': 'Instance state captured',
                'Timestamp': get_timestamp(),
                'InstanceId': instance_id
            })
        except Exception as e:
            evidence['InstanceCaptureError'] = str(e)
    
    return case_id, evidence

def isolate_instance(instance_id, case_id):
    # Isolate compromised instance by removing it from all security groups
    # and placing it in an isolated security group with no ingress or egress
    timestamp = get_timestamp()
    
    try:
        # Create an isolation security group if it doesn't exist
        try:
            isolation_sg = ec2.create_security_group(
                GroupName=f'ISOLATED-{case_id}',
                Description=f'Isolation group for IR case {case_id}'
            )
            sg_id = isolation_sg['GroupId']
        except ec2.exceptions.ClientError as e:
            if 'InvalidGroup.Duplicate' in str(e):
                # Group already exists - find it
                sgs = ec2.describe_security_groups(
                    Filters=[{'Name': 'group-name', 'Values': [f'ISOLATED-{case_id}']}]
                )
                sg_id = sgs['SecurityGroups'][0]['GroupId']
            else:
                raise e
        
        # Move instance to isolation security group
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[sg_id]
        )

        return {
            'Action': 'Instance isolated',
            'Timestamp': timestamp,
            'InstanceId': instance_id,
            'IsolationGroupId': sg_id,
            'Status': 'SUCCESS'
        }

    except Exception as e:
        return {
            'Action': 'Isolation attempted',
            'Timestamp': timestamp,
            'InstanceId': instance_id,
            'Status': 'FAILED',
            'Error': str(e)
        }
def get_guardduty_findings():
    # Get active high severity findings from GuardDuty
    try:
        # Get detector ID first
        detectors = guardduty.list_detectors()
        if not detectors['DetectorIds']:
            print("No GuardDuty detectors found")
            return []
        
        detector_id = detectors['DetectorIds'][0]
        
        # Get findings above our severity threshold
        finding_ids = guardduty.list_findings(
            DetectorId=detector_id,
            FindingCriteria={
                'Criterion': {
                    'severity': {
                        'Gte': int(SEVERITY_THRESHOLD)
                    }
                }
            }
        )
        
        if not finding_ids['FindingIds']:
            print("No high severity findings found")
            return []
        
        # Get full finding details
        findings = guardduty.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids['FindingIds']
        )
        
        return findings['Findings']
        
    except Exception as e:
        print(f"Error retrieving GuardDuty findings: {e}")
        return []

def save_evidence_to_s3(case_id, evidence):
    # Save evidence package to S3 with case ID as key
    # This preserves the evidence chain and makes it retrievable
    timestamp = get_timestamp()
    key = f"cases/{case_id}/evidence_{timestamp}.json"
    
    try:
        s3.put_object(
            Bucket=EVIDENCE_BUCKET,
            Key=key,
            Body=json.dumps(evidence, indent=4, default=str),
            ContentType='application/json',
            ServerSideEncryption='AES256'
        )
        print(f"Evidence saved to s3://{EVIDENCE_BUCKET}/{key}")
        return True
    except Exception as e:
        print(f"Failed to save evidence to S3: {e}")
        local_file = f"evidence_{case_id}.json"
        with open(local_file, 'w') as f:
            json.dump(evidence, f, indent=4, default=str)
        print(f"Evidence saved locally to {local_file} as fallback")
        return False

def respond_to_finding(finding):
    # Main response orchestrator - coordinates evidence capture and isolation
    print(f"\nResponding to finding: {finding.get('Type', 'unknown')}")
    print(f"Severity: {finding.get('Severity', 0)}")
    
    # Extract instance ID if this finding involves an EC2 instance
    instance_id = None
    try:
        instance_id = finding['Resource']['InstanceDetails']['InstanceId']
        print(f"Affected instance: {instance_id}")
    except KeyError:
        print("No EC2 instance associated with this finding")
    
    # Capture evidence first - always before taking any action
    case_id, evidence = capture_evidence(finding, instance_id)
    print(f"Case opened: {case_id}")
    
    # Isolate if we have an instance
    if instance_id:
        isolation_result = isolate_instance(instance_id, case_id)
        evidence['IsolationResult'] = isolation_result
        evidence['ChainOfCustody'].append(isolation_result)
        print(f"Isolation status: {isolation_result['Status']}")
    
    # Save everything to S3
    save_evidence_to_s3(case_id, evidence)
    
    return case_id, evidence
def generate_ir_report(cases):
    # Summary report of all cases handled in this run
    timestamp = get_timestamp()
    filename = f"reports/ir_report_{timestamp}.json"
    
    os.makedirs('reports', exist_ok=True)
    
    report = {
        'RunTime': timestamp,
        'TotalCases': len(cases),
        'Cases': cases
    }
    
    with open(filename, 'w') as f:
        json.dump(report, f, indent=4, default=str)
    
    print(f"\n=== IR Run Complete ===")
    print(f"Cases handled: {len(cases)}")
    print(f"Report saved to: {filename}")

def lambda_handler(event, context):
    # Entry point when running as AWS Lambda function
    # GuardDuty triggers this via EventBridge when a finding is created
    print("IR system triggered by Lambda event")
    
    finding = event.get('detail', {})
    if finding:
        case_id, evidence = respond_to_finding(finding)
        return {
            'statusCode': 200,
            'body': json.dumps({'CaseID': case_id})
        }
    return {
        'statusCode': 400,
        'body': json.dumps({'error': 'No finding in event'})
    }

if __name__ == "__main__":
    print("=== Automated Incident Response System ===")
    print(f"Severity threshold: {SEVERITY_THRESHOLD}+")
    print("Checking GuardDuty for active findings...\n")
    
    findings = get_guardduty_findings()
    print(f"Found {len(findings)} high severity findings")
    
    cases = []
    for finding in findings:
        case_id, evidence = respond_to_finding(finding)
        cases.append({'CaseID': case_id, 'Type': finding.get('Type')})
    
    generate_ir_report(cases)
