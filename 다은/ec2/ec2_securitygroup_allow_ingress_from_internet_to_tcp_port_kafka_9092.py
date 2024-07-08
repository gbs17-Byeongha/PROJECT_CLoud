import boto3
import json
import os
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

def get_aws_credentials():
    access_key = input("AWS Access Key: ")
    secret_key = input("AWS Secret Key: ")

    # 환경 변수에 AWS 자격 증명을 저장
    os.environ["AWS_ACCESS_KEY_ID"] = access_key
    os.environ["AWS_SECRET_ACCESS_KEY"] = secret_key

def check_security_group_ingress(ec2_client):
    try:
        response = ec2_client.describe_security_groups()
    except (NoCredentialsError, PartialCredentialsError):
        print("AWS 자격 증명이 없습니다. 자격 증명을 입력하세요.")
        get_aws_credentials()
        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_security_groups()

    check_ports = [9200, 9300, 5601]
    findings = []

    for security_group in response['SecurityGroups']:
        group_id = security_group['GroupId']
        group_name = security_group.get('GroupName', 'Unnamed')
        group_arn = security_group.get('GroupArn', 'N/A')
        group_tags = security_group.get('Tags', [])
        region = ec2_client.meta.region_name

        report = {
            "arn": group_arn,
            "tags": group_tags,
            "region": region,
            "policy_name": group_name,
            "status": "PASS",
            "details": f"보안 그룹 {group_name} ({group_id})는 Elasticsearch/Kibana 포트 9200, 9300 및 5601을 인터넷에 열지 않았습니다."
        }

        for ingress_rule in security_group.get('IpPermissions', []):
            if 'FromPort' in ingress_rule and 'ToPort' in ingress_rule:
                if ingress_rule['IpProtocol'] == 'tcp' and any(port in range(ingress_rule['FromPort'], ingress_rule['ToPort'] + 1) for port in check_ports):
                    for ip_range in ingress_rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            report["status"] = "FAIL"
                            report["details"] = f"보안 그룹 {group_name} ({group_id})는 Elasticsearch/Kibana 포트 9200, 9300 및 5601을 인터넷에 열었습니다."
                            break

        if report["status"] == "PASS":
            findings.append(report)
            break  # 첫 번째 PASS 상태의 보안 그룹만 찾으면 종료

    return findings

def save_findings_to_json(findings, filename):
	with open(filename, 'w') as file:
		json.dump(findings, file, indent=4)

if __name__ == "__main__":
    # boto3 클라이언트 초기화 (하드코딩된 AWS 접근 키와 비밀 키 사용)
    ec2_client = boto3.client(
        'ec2'
    )

    # 함수 호출 및 결과 저장
    result = check_security_group_ingress(ec2_client)
    if result:
        save_findings_to_json(result, 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_kafka_9092.json')
        # 결과를 JSON 형식으로 출력
        print(f"결과가 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_kafka_9092.json' 파일에 저장되었습니다.")
    else:
        print("보안 그룹 검사 중 오류가 발생했습니다.")
