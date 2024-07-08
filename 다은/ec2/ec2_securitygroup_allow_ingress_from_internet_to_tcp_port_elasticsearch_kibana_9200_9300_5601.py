import boto3
import os
import json
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

# AWS 접근을 위한 함수
def get_boto3_client(service):
    try:
        client = boto3.client(service)
        return client
    except (NoCredentialsError, PartialCredentialsError):
        access_key = input("AWS Access Key를 입력하세요: ")
        secret_key = input("AWS Secret Key를 입력하세요: ")
        os.environ['AWS_ACCESS_KEY_ID'] = access_key
        os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key
        client = boto3.client(service)
        return client

# 보안 그룹 체크 함수
def check_security_groups(ec2_client):
    try:
        response = ec2_client.describe_security_groups()
    except Exception as e:
        print(f"보안 그룹을 가져오는 중 오류 발생: {e}")
        return

    check_ports = [9200, 9300, 5601]
    for security_group in response['SecurityGroups']:
        report = {
            "arn": security_group.get('Arn', 'N/A'),
            "tags": security_group.get('Tags', []),
            "region": ec2_client.meta.region_name,
            "policy_name": security_group.get('GroupName', 'N/A'),
            "status": "PASS",
            "details": f"보안 그룹 {security_group.get('GroupName', 'N/A')} ({security_group.get('GroupId', 'N/A')})는 Elasticsearch/Kibana 포트 9200, 9300 및 5601을 인터넷에 열지 않았습니다."
        }

        for ingress_rule in security_group.get('IpPermissions', []):
            for ip_range in ingress_rule.get('IpRanges', []):
                if any(port in range(ingress_rule.get('FromPort', -1), ingress_rule.get('ToPort', -1)+1) for port in check_ports):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        report["status"] = "FAIL"
                        report["details"] = f"보안 그룹 {security_group.get('GroupName', 'N/A')} ({security_group.get('GroupId', 'N/A')})가 Elasticsearch/Kibana 포트 9200, 9300 및 5601을 인터넷에 열었습니다."
                        break

        # 첫 번째 보안 그룹만 반환
        return [report]

    return []

def save_findings_to_json(findings, filename):
    with open(filename, 'w', encoding='utf-8') as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    # boto3 클라이언트 초기화 (하드코딩된 AWS 접근 키와 비밀 키 사용)
    ec2_client = boto3.client(
        'ec2'
    )

    # 함수 호출 및 결과 저장
    result = check_security_groups(ec2_client)
    if result:
        save_findings_to_json(result, 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601.json')
        # 결과를 JSON 형식으로 출력
        print(f"결과가 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601.json' 파일에 저장되었습니다.")
    else:
        print("보안 그룹 검사 중 오류가 발생했습니다.")
