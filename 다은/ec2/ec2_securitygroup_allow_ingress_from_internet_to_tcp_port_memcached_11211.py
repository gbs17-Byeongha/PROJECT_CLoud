import boto3
import os
import json
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

def get_ec2_client():
    try:
        # 시도하여 AWS 클라이언트 생성
        return boto3.client('ec2')
    except (NoCredentialsError, PartialCredentialsError):
        # 사용자가 키값과 비밀키값을 입력
        access_key = input("Enter your AWS Access Key ID: ")
        secret_key = input("Enter your AWS Secret Access Key: ")

        # 환경 변수에 저장
        os.environ['AWS_ACCESS_KEY_ID'] = access_key
        os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key

        # 새로운 클라이언트 생성
        return boto3.client('ec2', 
                            aws_access_key_id=access_key,
                            aws_secret_access_key=secret_key)

def check_security_group_for_memcached(ec2_client):
    findings = []
    check_ports = [11211]
    
    response = ec2_client.describe_security_groups()
    security_groups = response.get('SecurityGroups', [])
    
    for security_group in security_groups:
        group_id = security_group.get('GroupId')
        vpc_id = security_group.get('VpcId')
        tags = security_group.get('Tags', [])
        region = ec2_client.meta.region_name
        ingress_rules = security_group.get('IpPermissions', [])

        status = "PASS"
        status_extended = f"Security group {group_id} does not have Memcached port 11211 open to the Internet."

        for ingress_rule in ingress_rules:
            from_port = ingress_rule.get('FromPort')
            to_port = ingress_rule.get('ToPort')
            ip_ranges = ingress_rule.get('IpRanges', [])

            if from_port == 11211 and to_port == 11211:
                for ip_range in ip_ranges:
                    cidr_ip = ip_range.get('CidrIp')
                    if cidr_ip == '0.0.0.0/0':
                        status = "FAIL"
                        status_extended = f"Security group {group_id} has Memcached port 11211 open to the Internet."
                        break
            if status == "FAIL":
                break

        finding = {
            'arn': f"arn:aws:ec2:{region}:{group_id}:security-group/{group_id}",
            'tags': tags,
            'region': region,
            'policy_name': 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211',
            'status': status,
            'details': status_extended
        }

        findings.append(finding)

        # 첫 번째 항목만 처리하기 위해 루프 종료
        break

    return findings

def save_findings_to_json(findings, filename):
    with open(filename, 'w') as file:
        json.dump(findings, file, indent=4)

if __name__ == "__main__":
    # 하드코딩된 AWS 자격 증명 사용
    ec2_client = boto3.client(
        'ec2'
    )

    # 함수 호출 및 결과 저장
    results = check_security_group_for_memcached(ec2_client)
    save_findings_to_json(results, 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211.json')
    
    # 결과를 JSON 형식으로 출력
    print("결과가 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211.json' 파일에 저장되었습니다.")
