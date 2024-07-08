import boto3
import json
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

def get_ec2_client(access_key, secret_key, region):
    try:
        return boto3.client(
            'ec2',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
    except (NoCredentialsError, PartialCredentialsError):
        print("AWS 자격 증명을 확인할 수 없습니다.")
        return None

def get_security_groups(ec2_client):
    try:
        response = ec2_client.describe_security_groups()
        return response['SecurityGroups']
    except Exception as e:
        print(f"보안 그룹을 가져오는 동안 오류가 발생했습니다: {e}")
        return []

def check_security_groups(ec2_client, max_rules=50):
    security_groups = get_security_groups(ec2_client)
    findings = []

    if security_groups:
        sg = security_groups[0]
        sg_id = sg['GroupId']
        sg_name = sg.get('GroupName', 'N/A')
        region = ec2_client.meta.region_name
        ingress_rules = sg.get('IpPermissions', [])
        egress_rules = sg.get('IpPermissionsEgress', [])
        tags = sg.get('Tags', [])

        status = "PASS"
        if len(ingress_rules) > max_rules or len(egress_rules) > max_rules:
            status = "FAIL"

        report = {
            'arn': f"arn:aws:ec2:{region}:{sg_id}",
            'tags': tags,
            'region': region,
            'policy_name': sg_name,
            'status': status,
            'detail': f"Security group {sg_name} ({sg_id}) has {len(ingress_rules)} inbound rules and {len(egress_rules)} outbound rules."
        }
        findings.append(report)

    return findings

def save_findings_to_json(findings, filename):
    with open(filename, 'w') as file:
        json.dump(findings, file, indent=4)

if __name__ == "__main__":
    # access_key = 
    # secret_key = 
    # region = "ap-northeast-2"

    # ec2_client = get_ec2_client(access_key, secret_key, region)

    ec2_client = boto3.client(
        'ec2'
    )

    if ec2_client:
        result = check_security_groups(ec2_client)
        save_findings_to_json(result, 'ec2_securitygroup_with_many_ingress_egress_rules.json')
        print(f"Results saved to 'ec2_securitygroup_with_many_ingress_egress_rules.json'.")
    else:
        print("EC2 클라이언트를 생성할 수 없습니다.")
