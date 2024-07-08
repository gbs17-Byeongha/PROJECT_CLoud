import boto3
import json
from botocore.exceptions import ClientError
from lib import check_network_acl  # lib 모듈에서 check_network_acl 함수 import

# 네트워크 ACL의 TCP 포트 3389(Microsoft RDP)가 인터넷에 노출되었는지 확인하는 함수
def ec2_networkacl_allow_ingress_tcp_port_3389_1(ec2_client):
    findings = []  # 결과를 저장할 리스트 초기화
    tcp_protocol = "6"  # TCP 프로토콜 번호 (6)
    check_port = 3389  # 확인할 포트 번호 (Microsoft RDP 포트)

    try:
        # 모든 네트워크 ACL 정보를 가져오기
        response = ec2_client.describe_network_acls()
        network_acls = response['NetworkAcls']
        ec2_resource = boto3.resource('ec2')  # EC2 리소스 객체 생성

        for network_acl in network_acls:
            vpc_id = network_acl['VpcId']  # ACL이 속한 VPC ID
            vpc = ec2_resource.Vpc(vpc_id)
            region = vpc.meta.client.meta.region_name  # ACL이 속한 리전 가져오기

            report = {
                # "Object_name": network_acl['NetworkAclId'],  # ACL ID
                "arn": network_acl['NetworkAclId'],  # ACL ARN
                "region": region,  # 리전 이름
                "status": "PASS",  # 기본 상태 'PASS'
                "status_extended": f"Network ACL {network_acl['NetworkAclId']} does not have Microsoft RDP port 3389 open to the Internet."  # 상태 확장 설명
            }

            # 네트워크 ACL의 Entry들을 확인하여 Microsoft RDP 포트 3389가 인터넷에 열려 있는지 검사
            if check_network_acl(network_acl['Entries'], tcp_protocol, check_port):
                report["status"] = "FAIL"
                report["status_extended"] = f"Network ACL {network_acl['NetworkAclId']} has Microsoft RDP port 3389 open to the Internet."

            findings.append(report)  # 결과를 리스트에 추가
    except ClientError as e:
        # 예외 처리: 네트워크 ACL 정보를 가져오는 중 오류 발생
        findings.append({
            # "Object_name": "N/A",  # 객체 이름이 없음
            "arn": "N/A",  # ARN이 없음
            "region": "N/A",  # 리전 정보가 없음
            "status": "ERROR",  # 상태 'ERROR'
            "status_extended": f"Error retrieving network ACL information: {str(e)}"  # 상세 오류 메시지
        })

    return findings  # 최종 결과 반환

if __name__ == "__main__":
    ec2_client = boto3.client('ec2')  # EC2 클라이언트 생성

    result = ec2_networkacl_allow_ingress_tcp_port_3389_1(ec2_client)  # 함수 호출하여 결과 저장

    print(json.dumps(result, indent=4))  # 결과를 JSON 형식으로 출력

    # 결과를 JSON 형식으로 파일에 저장하는 경우 (필요 시 주석 해제)
    # with open('ec2_networkacl_allow_ingress_tcp_port_3389_results.json', 'w') as json_file:
    #     json.dump(result, json_file, indent=4)
