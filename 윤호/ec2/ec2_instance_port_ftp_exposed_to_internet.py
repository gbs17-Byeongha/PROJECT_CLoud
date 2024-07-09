import boto3
import json

def check_ec2_instance_port_ftp_exposed_to_internet(ec2_client):
    """
    EC2 인스턴스의 FTP 포트(20, 21)가 인터넷에 노출되어 있는지 확인합니다.
    """
    findings = []
    check_ports = [20, 21]  # 확인할 FTP 포트 번호

    # 모든 EC2 인스턴스 가져오기
    instances = ec2_client.describe_instances()

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            status = "PASS"  # 기본 상태는 PASS로 설정
            status_extended = f"인스턴스 {instance_id}에 인터넷에 열려 있는 FTP 포트가 없습니다."
            severity = "low"  # 기본 심각도는 낮음

            # 인스턴스의 보안 그룹 확인
            for sg in instance['SecurityGroups']:
                security_group_id = sg['GroupId']
                security_group = ec2_client.describe_security_groups(GroupIds=[security_group_id])

                for rule in security_group['SecurityGroups'][0]['IpPermissions']:
                    # TCP 프로토콜이고 FTP 포트가 열려있는지 확인
                    if rule.get('IpProtocol') == 'tcp' and any(
                        rule.get('FromPort') <= port_num <= rule.get('ToPort')
                        for port_num in check_ports
                    ):
                        # 0.0.0.0/0 또는 ::/0로 열려있는지 확인
                        if any(ip_range['CidrIp'] in ['0.0.0.0/0', '::/0'] for ip_range in rule.get('IpRanges', [])):
                            status = "FAIL"  # 상태를 FAIL로 변경
                            severity = "critical" if 'PublicIpAddress' in instance else "high"  # Public IP 여부에 따라 심각도 설정
                            status_extended = (
                                f"인스턴스 {instance_id}는 FTP 포트가 인터넷에 개방되어 있습니다 "
                                f"{'그리고 공인 IP를 가지고 있습니다' if 'PublicIpAddress' in instance else '하지만 공인 IP가 없습니다'}."
                            )
                            break

                if status == "FAIL":
                    break

            # 결과를 finding에 저장
            finding = {
                'ResourceId': instance_id,
                'ResourceArn': instance.get('InstanceArn', ''),
                'Status': status,
                'StatusExtended': status_extended,
                'Severity': severity,
                'Region': instance['Placement']['AvailabilityZone'][:-1],
                'Tags': [{t['Key']: t['Value']} for t in instance.get('Tags', [])]
            }
            findings.append(finding)

    results = []
    for finding in findings:
        # 결과를 정리하여 저장
        result = {
            'arn': finding['ResourceArn'],
            'tag': finding['Tags'],
            'region': finding['Region'],
            'policy_name': '',  # EC2 인스턴스에는 정책 이름이 해당되지 않음
            'status': finding['Status'],
            'status_extended': finding['StatusExtended']
        }
        results.append(result)

    return results

def save_findings_to_json(findings, filename):
    # 결과를 JSON 파일로 저장
    with open(filename, 'w',encoding='UTF-8-sig') as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)

if __name__ == '__main__':
    ec2_client = boto3.client('ec2')
    results = check_ec2_instance_port_ftp_exposed_to_internet(ec2_client)
    
    # 결과 출력 (예: JSON 파일로 저장)
    save_findings_to_json(results, "ec2_instance_port_ftp_exposed_to_internet.json")
    print("Results saved to 'ec2_instance_port_ftp_exposed_to_internet.json'")
