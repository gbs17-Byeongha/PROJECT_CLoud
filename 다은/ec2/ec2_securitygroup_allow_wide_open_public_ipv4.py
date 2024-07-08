import boto3
import ipaddress
import os
import json
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

def set_aws_credentials():
    access_key = input("Enter your AWS Access Key: ")
    secret_key = input("Enter your AWS Secret Key: ")
    os.environ["AWS_ACCESS_KEY_ID"] = access_key
    os.environ["AWS_SECRET_ACCESS_KEY"] = secret_key

def get_ec2_security_groups(ec2_client):
    try:
        response = ec2_client.describe_security_groups()
        return response['SecurityGroups']
    except (NoCredentialsError, PartialCredentialsError):
        set_aws_credentials()
        return get_ec2_security_groups(ec2_client)
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

def check_security_group_rules(security_groups, region, target_group_name="default"):
    findings = []
    cidr_threshold = 24
    for sg in security_groups:
        if sg.get('GroupName') == target_group_name:
            sg_id = sg['GroupId']
            sg_arn = sg.get('Arn', 'N/A')
            sg_tags = sg.get('Tags', [])

            report = {
                "arn": sg_arn,
                "tags": sg_tags,
                "region": region,
                "policy_name": "N/A",
                "status": "PASS",
                "details": f"Security group ({sg_id}) has no potential wide-open non-RFC1918 address."
            }

            def check_rules(rules, rule_type):
                for rule in rules:
                    for ipv4 in rule.get("IpRanges", []):
                        ip = ipaddress.ip_network(ipv4["CidrIp"])
                        if ip.is_global and 0 < ip.prefixlen < cidr_threshold:
                            report["policy_name"] = rule_type
                            report["status"] = "FAIL"
                            report["details"] = f"Security group ({sg_id}) has potential wide-open non-RFC1918 address {ipv4['CidrIp']} in {rule_type} rule."
                            return

            check_rules(sg.get('IpPermissions', []), 'ingress')
            if report["status"] == "PASS":
                check_rules(sg.get('IpPermissionsEgress', []), 'egress')

            findings.append(report)

    return findings

def save_findings_to_json(findings, filename):
    with open(filename, 'w') as file:
        json.dump(findings, file, indent=4)

if __name__ == "__main__":
    ec2_client = boto3.client(
        'ec2'
    )

    # EC2 보안 그룹 가져오기
    security_groups = get_ec2_security_groups(ec2_client)

    # 특정 보안 그룹 규칙 검사 (여기서 "default" 보안 그룹만 검사)
    findings = check_security_group_rules(security_groups, 'ap-northeast-2', target_group_name="default")

    if findings:
        # 첫 번째 결과만 출력
        result_to_save = findings[0]
        print(json.dumps(result_to_save, indent=4))

        # 결과를 JSON 파일로 저장
        save_findings_to_json([result_to_save], 'ec2_securitygroup_allow_wide_open_public_ipv4.json')
    else:
        print("No findings for the specified security group.")
