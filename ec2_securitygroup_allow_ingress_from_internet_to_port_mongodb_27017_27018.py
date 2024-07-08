import boto3
import json
from botocore.exceptions import ClientError

# 보안 그룹의 MongoDB 포트가 인터넷에 오픈되어 있는지 확인하는 함수
def ec2_securitygroup_allow_ingress_from_internet_to_mongodb_ports(ec2_client):
    findings = []  # 결과를 저장할 리스트 초기화
    check_ports = [27017, 27018]  # 확인할 MongoDB 포트 리스트

    try:
        # 모든 보안 그룹 정보를 가져오기
        security_groups = ec2_client.describe_security_groups()['SecurityGroups']

        for security_group in security_groups:
            vpc_id = security_group['VpcId']
            
            # 보안 그룹에 연결된 네트워크 인터페이스가 있는지 확인
            network_interfaces = ec2_client.describe_network_interfaces(
                Filters=[{'Name': 'group-id', 'Values': [security_group['GroupId']]}]
            )['NetworkInterfaces']
            
            if len(network_interfaces) > 0:
                # 보고서 초기화
                report = {
                    # "Object_name": security_group.get('GroupName', ''),  # 보안 그룹 이름
                    "arn": security_group['GroupId'],  # ARN은 그룹 ID로 설정
                    "region": security_group.get('VpcId', 'N/A'),  # 보안 그룹이 속한 VPC ID, 없으면 'N/A'
                    "status": "PASS",  # 기본 상태 'PASS'
                    "status_extended": f"Security group {security_group.get('GroupName', '')} ({security_group['GroupId']}) does not have MongoDB ports 27017 and 27018 open to the Internet."  # 상태 확장 설명
                }
                
                # 모든 인그레스 규칙 검사
                for ingress_rule in security_group['IpPermissions']:
                    if ingress_rule['IpProtocol'] == 'tcp' and any(
                        ip_range['CidrIp'] == '0.0.0.0/0' for ip_range in ingress_rule.get('IpRanges', [])
                    ) and any(
                        port in range(ingress_rule.get('FromPort', -1), ingress_rule.get('ToPort', -1) + 1) for port in check_ports
                    ):
                        report["status"] = "FAIL"
                        report["status_extended"] = f"Security group {security_group.get('GroupName', '')} ({security_group['GroupId']}) has MongoDB ports 27017 and 27018 open to the Internet."
                        break

                findings.append(report)  # 보고서를 결과 리스트에 추가
    except ClientError as e:
        # 예외 처리: 보안 그룹 정보를 가져오는 중 오류 발생
        findings.append({
            # "Object_name": "N/A",  # 객체 이름이 없음
            "arn": "N/A",  # ARN이 없음
            "region": "N/A",  # 리전 정보가 없음
            "status": "ERROR",  # 상태 'ERROR'
            "status_extended": f"Error retrieving security group information: {str(e)}"  # 상세 오류 메시지
        })

    return findings  # 최종 결과 반환

if __name__ == "__main__":
    # AWS EC2 클라이언트 생성
    ec2_client = boto3.client('ec2')

    # 함수 호출 및 결과 저장
    result = ec2_securitygroup_allow_ingress_from_internet_to_mongodb_ports(ec2_client)

    # 결과를 JSON 형식으로 출력
    print(json.dumps(result, indent=4))

    # 결과를 JSON 형식으로 파일에 저장하는 경우 (필요 시 주석 해제)
    # with open('ec2_securitygroup_allow_ingress_mongodb_ports_results.json', 'w') as json_file:
    #     json.dump(result, json_file, indent=4)
