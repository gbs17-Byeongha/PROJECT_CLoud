import boto3
import json
from botocore.exceptions import ClientError
from lib import *  # 보조 함수들 포함 (예: check_security_group, get_instance_public_status)

# VPC 클라이언트를 사용하여 서브넷 정보를 가져와서 public 여부를 확인하는 함수
def get_vpc_subnets(vpc_client):
    # 모든 서브넷 정보를 가져옴
    subnets = vpc_client.describe_subnets()
    # 각 서브넷의 ID와 public 여부를 저장할 딕셔너리 생성
    vpc_subnets = {
        subnet['SubnetId']: {
            'Public': any(attr['Key'] == 'mapPublicIpOnLaunch' and attr['Value'] == 'true' for attr in subnet.get('Tags', []))
        } for subnet in subnets['Subnets']
    }
    return vpc_subnets

# EC2 인스턴스의 Telnet 포트가 인터넷에 노출되었는지 확인하는 함수
def ec2_instance_port_telnet_exposed_to_internet2(ec2_client):
    findings = []  # 결과를 저장할 리스트 초기화
    check_ports = [23]  # 검사할 포트 (여기서는 Telnet 포트 23)

    try:
        # VPC 클라이언트 생성
        vpc_client = boto3.client('ec2')
        # 서브넷 정보 가져오기
        vpc_subnets = get_vpc_subnets(vpc_client)

        # 모든 인스턴스 정보 가져오기
        instances = ec2_client.describe_instances()

        # 모든 인스턴스를 반복하면서 검사
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                report = {
                    # "Object_name": instance['InstanceId'],  # 인스턴스 ID
                    "arn": instance['InstanceId'],  # 인스턴스 ARN
                    "tag": instance.get('Tags', []),  # 인스턴스 태그
                    "region": instance['Placement']['AvailabilityZone'],  # 인스턴스가 위치한 가용 영역
                    "status": "PASS",  # 기본 상태는 'PASS'
                    "status_extended": f"Instance {instance['InstanceId']} does not have Telnet port 23 open to the Internet."
                }
                is_open_port = False  # 포트가 열려 있는지 여부

                # 인스턴스의 보안 그룹을 검사
                if instance['SecurityGroups']:
                    for sg in instance['SecurityGroups']:
                        sg_id = sg['GroupId']
                        # 보안 그룹 정보 가져오기
                        security_group = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
                        for ingress_rule in security_group['IpPermissions']:
                            # 보안 그룹 규칙이 특정 조건을 만족하는지 검사
                            if check_security_group(ingress_rule, "tcp", check_ports, any_address=True):
                                report["status"] = "FAIL"
                                report["status_extended"], report["severity"] = get_instance_public_status(vpc_subnets, instance, "Telnet")
                                is_open_port = True
                                break
                        if is_open_port:
                            break

                findings.append(report)  # 보고서에 결과 추가
    except ClientError as e:
        # 오류 발생 시 결과에 오류 정보를 추가
        findings.append({
            "Object_name": "N/A",
            "arn": "N/A",
            "tag": "N/A",
            "region": "N/A",
            "status": "ERROR",
            "status_extended": f"Error retrieving EC2 instance information: {str(e)}"
        })

    return findings  # 결과 리스트 반환

if __name__ == "__main__":
    # EC2 클라이언트 객체 생성
    ec2_client = boto3.client('ec2')

    # Telnet 포트가 인터넷에 노출되었는지 검사
    result = ec2_instance_port_telnet_exposed_to_internet2(ec2_client)

    # 결과를 JSON 형식으로 출력
    print(json.dumps(result, indent=4))

    # 결과를 JSON 형식으로 파일 만들기 (필요 시 주석 해제)
    # with open('ec2_instance_port_telnet_exposed_to_internet_results.json', 'w') as json_file:
    #     json.dump(result, json_file, indent=4)
