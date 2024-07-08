import boto3
import os
import json
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

def set_aws_credentials():
    access_key = input("Enter your AWS Access Key: ")
    secret_key = input("Enter your AWS Secret Key: ")

    os.environ['AWS_ACCESS_KEY_ID'] = access_key
    os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key

def get_ec2_client():
    try:
        return boto3.client('ec2')
    except (NoCredentialsError, PartialCredentialsError):
        print("AWS credentials not found or incomplete. Please enter your credentials.")
        set_aws_credentials()
        return boto3.client('ec2')

def check_security_group_ingress_for_sql_server_ports(ec2_client):
    check_ports = [1433, 1434]
    findings = []

    try:
        response = ec2_client.describe_security_groups()
    except Exception as e:
        print(f"Error describing security groups: {str(e)}")
        return []

    for security_group in response['SecurityGroups']:
        report = {
            'arn': security_group.get('Arn', 'N/A'),
            'tags': security_group.get('Tags', []),
            'region': ec2_client.meta.region_name,
            'policy_name': security_group['GroupName'],
            'status': "PASS",
            'detail': f"Security group {security_group['GroupName']} ({security_group['GroupId']}) does not have Microsoft SQL Server ports 1433 and 1434 open to the Internet."
        }

        for ingress_rule in security_group.get('IpPermissions', []):
            ip_ranges = ingress_rule.get('IpRanges', [])
            if ingress_rule.get('FromPort') in check_ports and ingress_rule.get('ToPort') in check_ports:
                for ip_range in ip_ranges:
                    if ip_range.get('CidrIp') == '0.0.0.0/0':  # Checking if the rule allows access from the Internet
                        report['status'] = "FAIL"
                        report['detail'] = f"Security group {security_group['GroupName']} ({security_group['GroupId']}) has Microsoft SQL Server ports 1433 and 1434 open to the Internet."
                        break

        findings.append(report)

    # Filter findings to include only the first security group that passes the condition
    filtered_findings = [finding for finding in findings if finding['status'] == "PASS"]
    return filtered_findings[:1]  # Return only the first matched security group

def save_findings_to_json(findings, filename):
    with open(filename, 'w', encoding='utf-8') as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    ec2_client = boto3.client(
        'ec2'
    )

    # 함수 호출 및 결과 저장
    result = check_security_group_ingress_for_sql_server_ports(ec2_client)
    save_findings_to_json(result, 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434.json')

    # 결과를 JSON 형식으로 출력
    print(f"Results saved to 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434.json'.")
