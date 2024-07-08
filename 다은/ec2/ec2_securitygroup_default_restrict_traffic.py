import boto3
import json
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

def get_ec2_client(access_key, secret_key, region):
    try:
        return boto3.client('ec2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    except (NoCredentialsError, PartialCredentialsError):
        print("Credentials are not available.")
        return None

def execute(ec2_client, region):
    findings = []
    security_groups = ec2_client.describe_security_groups()['SecurityGroups']

    for security_group in security_groups:
        if security_group['GroupName'] == 'default':
            vpc_id = security_group['VpcId']
            vpcs = ec2_client.describe_vpcs(VpcIds=[vpc_id])['Vpcs']
            in_use = any(vpc for vpc in vpcs if vpc['VpcId'] == vpc_id)

            if in_use:
                report = {
                    'arn': '',  # ARN 정보는 describe_security_groups로는 제공되지 않음
                    'tags': security_group.get('Tags', []),
                    'region': region,  # 올바른 region 값을 설정
                    'status': 'PASS',  # 기본적으로 'PASS'로 설정
                    'details': f"Default Security Group ({security_group['GroupId']}) is in use."
                }

                findings.append(report)
                break  # 첫 번째 default security group을 찾으면 루프 종료

    return findings

def save_findings_to_json(findings, filename):
    with open(filename, 'w') as file:
        json.dump(findings, file, indent=4)

if __name__ == "__main__":
    # # AWS 자격 증명 하드코딩
    # AWS_ACCESS_KEY = 
    # AWS_SECRET_KEY =
    REGION_NAME = 'ap-northeast-2'

    # # EC2 클라이언트 생성
    # ec2_client = get_ec2_client(AWS_ACCESS_KEY, AWS_SECRET_KEY, REGION_NAME)

    ec2_client = boto3.client(
        'ec2'
    )

    if (ec2_client):
        # 함수 호출 및 결과 저장
        result = execute(ec2_client, REGION_NAME)  # region을 인자로 전달
        save_findings_to_json(result, 'ec2_securitygroup_default_restrict_traffic.json')
        # 결과를 JSON 형식으로 출력
        print(f"Results saved to 'ec2_securitygroup_default_restrict_traffic.json'.")
    else:
        print("Failed to create EC2 client due to credential issues.")
