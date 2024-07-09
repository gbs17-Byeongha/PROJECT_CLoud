import json
import boto3

def check_ec2_instance_port_cifs_exposed_to_internet(ec2_client):
    """
    EC2 인스턴스가 인터넷에서 TCP 포트 139 또는 445(CIFS)로의 인바운드 트래픽을 허용하는지 확인합니다.
    이는 잠재적인 보안 위험을 식별하는 데 도움이 됩니다.
    """
    findings = []
    check_ports = [139, 445]

    # 모든 EC2 인스턴스 가져오기
    instances = ec2_client.describe_instances()

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            owner_id = instance.get('OwnerId', 'unknown-owner')
            instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{owner_id}:instance/{instance_id}"
            
            status = "PASS"
            status_extended = f"인스턴스 {instance_id}에 인터넷에 열려 있는 CIFS 포트가 없습니다."

            # 인스턴스에 연결된 보안 그룹 확인
            for sg in instance['SecurityGroups']:
                security_group = ec2_client.describe_security_groups(GroupIds=[sg['GroupId']])
                
                # 보안 그룹의 인바운드 규칙 확인
                for rule in security_group['SecurityGroups'][0]['IpPermissions']:
                    if rule.get('IpProtocol') == 'tcp':
                        from_port = rule.get('FromPort', 0)
                        to_port = rule.get('ToPort', 65535)
                        
                        # CIFS 포트(139, 445)가 인바운드 규칙에 포함되는지 확인
                        if any(port in range(from_port, to_port + 1) for port in check_ports):
                            for ip_range in rule.get('IpRanges', []):
                                # 인바운드 규칙이 0.0.0.0/0 (모든 IP) 인지 확인
                                if ip_range.get('CidrIp') == '0.0.0.0/0':
                                    status = "FAIL"
                                    status_extended = f"인스턴스 {instance_id}에 인터넷에 CIFS 포트가 열려 있습니다."
                                    break
                    
                    if status == "FAIL":
                        break
                
                if status == "FAIL":
                    break

            # 결과 저장
            finding = {
                'ResourceId': instance_id,
                'ResourceArn': instance_arn,
                'Region': instance['Placement']['AvailabilityZone'][:-1],
                'Tags': [{t['Key']: t['Value']} for t in instance.get('Tags', [])],
                'Status': status,
                'StatusExtended': status_extended
            }
            findings.append(finding)

    results = []
    for finding in findings:
        result = {
            'arn': finding['ResourceArn'],
            'tag': finding['Tags'],
            'region': finding['Region'],
            'policy_name': '',  # Policy name is not applicable for EC2 instances
            'status': finding['Status'],
            'status_extended': finding['StatusExtended']
        }
        results.append(result)

    return results

def save_findings_to_json(findings, filename):
    # 결과를 JSON 파일로 저장
    with open(filename, 'w',encoding='UTF-8-sig') as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)

# 결과 실행 및 출력
if __name__ == '__main__':
    ec2_client = boto3.client('ec2')
    result = check_ec2_instance_port_cifs_exposed_to_internet(ec2_client)
    save_findings_to_json(result, "ec2_instance_port_cifs_exposed_to_internet.json")
    print("Results saved to 'ec2_instance_port_cifs_exposed_to_internet.json'")
