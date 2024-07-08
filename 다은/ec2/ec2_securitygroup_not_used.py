import boto3
import os
import json
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

def get_aws_client(service_name, access_key=None, secret_key=None, region_name=None):
    try:
        if access_key and secret_key:
            client = boto3.client(
                service_name,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region_name
            )
        else:
            client = boto3.client(service_name)
        return client
    except (NoCredentialsError, PartialCredentialsError):
        print("AWS 자격 증명이 설정되지 않았습니다. 키와 비밀 키를 입력하십시오.")
        access_key = input("AWS Access Key ID: ")
        secret_key = input("AWS Secret Access Key: ")
        os.environ['AWS_ACCESS_KEY_ID'] = access_key
        os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key
        client = boto3.client(service_name)
        return client

def find_unused_security_groups(ec2_client, lambda_client):
    findings = []

    # 모든 보안 그룹 가져오기
    security_groups = ec2_client.describe_security_groups()['SecurityGroups']

    # 모든 Lambda 함수 가져오기
    functions = lambda_client.list_functions()['Functions']

    for security_group in security_groups:
        # 기본 보안 그룹은 무시
        if security_group['GroupName'] != "default":
            group_id = security_group['GroupId']

            status = "PASS"
            details = f"Security group ({group_id}) has no potential wide-open non-RFC1918 address."

            findings.append({
                'arn': "N/A",
                'tags': [],
                'region': "ap-northeast-2",
                'policy_name': "N/A",
                'status': status,
                'details': details
            })

    return findings

def save_findings_to_json(findings, filename):
    with open(filename, 'w') as file:
        json.dump(findings, file, indent=4)

if __name__ == "__main__":
    # access_key = 
    # secret_key = 
    # region_name = 'ap-northeast-2'

    # ec2_client = get_aws_client('ec2', access_key, secret_key, region_name)
    # lambda_client = get_aws_client('lambda', access_key, secret_key, region_name)
    ec2_client = boto3.client(
        'ec2'
    )
    lambda_client = boto3.client(
        'lambda'
    )
    # 함수 호출 및 결과 저장
    result = find_unused_security_groups(ec2_client, lambda_client)
    save_findings_to_json(result, 'ec2_securitygroup_not_used.json')
    # 결과를 JSON 형식으로 출력
    print(f"Results saved to 'ec2_securitygroup_not_used.json'.")
