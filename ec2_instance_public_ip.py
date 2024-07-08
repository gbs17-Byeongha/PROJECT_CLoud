import json
import boto3
from botocore.exceptions import ClientError

# EC2 인스턴스의 공용 IP 여부를 확인하는 함수
def ec2_instance_public_ip2(ec2_client):
    findings = []  # 결과를 저장할 리스트 초기화

    try:
        # 모든 인스턴스 정보를 가져오기
        instances = ec2_client.describe_instances()
        # 인스턴스 정보를 반복하며 검사
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                # 종료된 인스턴스는 제외
                if instance['State']['Name'] != "terminated":
                    # 보고서 생성
                    report = {
                        "arn": instance['InstanceId'],  # 인스턴스 ID
                        "tag": instance.get('Tags', []),  # 인스턴스 태그
                        "region": instance['Placement']['AvailabilityZone'],  # 인스턴스가 위치한 가용 영역
                        "policy_name": "N/A",  # 정책 이름 (해당 없음)
                        "status": "PASS",  # 기본 상태는 'PASS'
                        "status_extended": f"EC2 Instance {instance['InstanceId']} does not have a Public IP."  # 기본 상태 설명
                    }
                    # 인스턴스에 공용 IP가 있는지 확인
                    if 'PublicIpAddress' in instance:
                        report["status"] = "FAIL"
                        report["status_extended"] = f"EC2 Instance {instance['InstanceId']} has a Public IP: {instance['PublicIpAddress']} ({instance.get('PublicDnsName', 'No DNS')})."
                    
                    # 보고서를 결과 리스트에 추가
                    findings.append(report)
    except ClientError as e:
        # 오류 발생 시 결과에 오류 정보를 추가
        findings.append({
            "arn": "N/A",
            "tag": "N/A",
            "region": "N/A",
            "policy_name": "N/A",
            "status": "ERROR",
            "status_extended": f"Error retrieving EC2 instance information: {str(e)}"
        })

    return findings  # 결과 리스트 반환

if __name__ == "__main__":
    # AWS EC2 클라이언트 생성
    ec2_client = boto3.client('ec2')

    # 함수 호출 및 결과 저장
    result = ec2_instance_public_ip2(ec2_client)

    # 결과를 JSON 형식으로 출력
    print(json.dumps(result, indent=4))

    # 결과를 JSON 형식으로 파일 저장 (필요 시 주석 해제)
    # with open('ec2_instance_public_ip_results.json', 'w') as json_file:
    #     json.dump(result, json_file, indent=4)
