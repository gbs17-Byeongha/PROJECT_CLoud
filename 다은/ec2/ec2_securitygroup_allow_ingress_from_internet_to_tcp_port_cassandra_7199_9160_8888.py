import boto3
import os
import json
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

def get_aws_credentials():
    access_key = input("AWS Access Key를 입력하세요: ")
    secret_key = input("AWS Secret Key를 입력하세요: ")
    os.environ['AWS_ACCESS_KEY_ID'] = access_key
    os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key

def check_security_group_ports(ec2):
    try:
        # 모든 보안 그룹 가져오기
        response = ec2.describe_security_groups()
        security_groups = response['SecurityGroups']

        check_ports = [7199, 9160, 8888]
        findings = []

        for security_group in security_groups:
            group_id = security_group['GroupId']
            group_name = security_group.get('GroupName', 'N/A')
            vpc_id = security_group.get('VpcId', 'N/A')
            region = ec2.meta.region_name

            report = {
                'arn': f"arn:aws:ec2:{region}:{group_id}",
                'tags': security_group.get('Tags', []),
                'region': region,
                'policy_name': group_name,
                'status': 'PASS',
                'detail': f"Security group {group_name} ({group_id}) does not have Cassandra ports 7199, 8888, and 9160 open to the Internet."
            }

            for permission in security_group['IpPermissions']:
                if permission.get('IpProtocol') == 'tcp' and 'FromPort' in permission and 'ToPort' in permission:
                    from_port = permission['FromPort']
                    to_port = permission['ToPort']
                    if any(port in range(from_port, to_port + 1) for port in check_ports):
                        for ip_range in permission.get('IpRanges', []):
                            if '0.0.0.0/0' == ip_range.get('CidrIp'):
                                report['status'] = 'FAIL'
                                report['detail'] = f"Security group {group_name} ({group_id}) has Cassandra ports 7199, 8888, and 9160 open to the Internet."
                                break

            findings.append(report)
            if report['status'] == 'PASS':
                return [report]  # 조건을 만족하는 첫 번째 보안 그룹만 반환

        return findings

    except (NoCredentialsError, PartialCredentialsError):
        print("AWS 자격 증명이 없습니다. 키값과 비밀키값을 입력해주세요.")
        get_aws_credentials()
        return check_security_group_ports(ec2)
    except Exception as e:
        print(f"오류 발생: {str(e)}")
        return [{
            'arn': 'N/A',
            'tags': [],
            'region': 'N/A',
            'policy_name': 'N/A',
            'status': 'ERROR',
            'details': f"오류 발생: {str(e)}"
        }]

def save_findings_to_json(findings, filename):
    with open(filename, 'w') as file:
        json.dump(findings, file, indent=4)

if __name__ == "__main__":
    # AWS IAM 클라이언트 생성
    ec2_client = boto3.client(
        'ec2'
    )

    # 함수 호출 및 결과 저장
    result = check_security_group_ports(ec2_client)
    save_findings_to_json(result, 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_cassandra_7199_9160_8888.json')
    # 결과를 JSON 형식으로 출력
    print(f"결과가 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_cassandra_7199_9160_8888.json' 파일에 저장되었습니다.")
