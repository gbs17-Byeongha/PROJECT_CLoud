import json
import boto3

def check_ec2_instance_port_rdp_exposed_to_internet(ec2_client):
    '''
    RDP 포트(3389)가 인터넷에 노출되어 있는지 점검
    '''
    findings = []

    # 모든 EC2 인스턴스 가져오기
    instances = ec2_client.describe_instances()

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            owner_id = instance.get('OwnerId', 'unknown-owner')
            instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{owner_id}:instance/{instance_id}"
            
            # 인스턴스에 공인 IP가 있는지 확인
            public_ip = instance.get('PublicIpAddress', None)
            
            # 인스턴스에 연결된 보안 그룹 가져오기
            security_groups = instance.get('SecurityGroups', [])
            
            is_rdp_open = False
            for sg in security_groups:
                sg_id = sg['GroupId']
                security_group = ec2_client.describe_security_groups(GroupIds=[sg_id])
                
                # 인바운드 규칙 확인
                for rule in security_group['SecurityGroups'][0]['IpPermissions']:
                    if 'FromPort' in rule and 'ToPort' in rule and rule['FromPort'] <= 3389 <= rule['ToPort']:
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range['CidrIp'] == '0.0.0.0/0':  # 전체 인터넷에 공개된 경우
                                is_rdp_open = True
                                break
                        if is_rdp_open:
                            break
                if is_rdp_open:
                    break
            
            if is_rdp_open and public_ip:
                status = "FAIL"
                status_extended = f"인스턴스 {instance_id}에 RDP 포트 3389가 인터넷에 열려 있고 공용 IP가 있습니다."
            elif is_rdp_open:
                status = "FAIL"
                status_extended = f"인스턴스 {instance_id}에 RDP 포트 3389가 인터넷에 열려 있지만 공용 IP가 없습니다."
            else:
                status = "PASS"
                status_extended = f"인스턴스 {instance_id}에 인터넷에 열려 있는 RDP 포트 3389가 없습니다."

            finding = {
                'arn': instance_arn,
                'tag': [{t['Key']: t['Value']} for t in instance.get('Tags', [])],
                'region': instance['Placement']['AvailabilityZone'][:-1],
                'policy_name': '',  # EC2 인스턴스에는 적용되지 않음
                'status': status,
                'status_extended': status_extended
            }
            findings.append(finding)

    return findings

def save_findings_to_json(findings, filename):
    # 결과를 JSON 파일로 저장
    with open(filename, 'w',encoding='UTF-8-sig') as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)

if __name__ == '__main__':
    ec2_client = boto3.client('ec2')
    result = check_ec2_instance_port_rdp_exposed_to_internet(ec2_client)
    save_findings_to_json(result, "ec2_instance_port_rdp_exposed_to_internet.json")
    print("Results saved to 'ec2_instance_port_rdp_exposed_to_internet.json'")
