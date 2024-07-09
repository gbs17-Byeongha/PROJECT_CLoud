import json
import boto3

def check_ec2_instance_port_redis_exposed_to_internet(ec2_client):
    '''
    Redis 포트(6379)가 인터넷에 노출되어 있는지 점검
    '''
    findings = []

    # 모든 EC2 인스턴스를 가져옵니다.
    instances = ec2_client.describe_instances()

    # 각 인스턴스를 순회합니다.
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            owner_id = instance.get('OwnerId', 'unknown-owner')
            instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{owner_id}:instance/{instance_id}"
            
            # 인스턴스에 공인 IP가 있는지 확인합니다.
            public_ip = instance.get('PublicIpAddress')
            
            # 인스턴스에 연결된 보안 그룹을 가져옵니다.
            security_groups = instance['SecurityGroups']
            
            is_redis_exposed = False
            # 각 보안 그룹을 순회합니다.
            for sg in security_groups:
                security_group_id = sg['GroupId']
                security_group = ec2_client.describe_security_groups(GroupIds=[security_group_id])['SecurityGroups'][0]
                
                # 보안 그룹의 인바운드 규칙을 확인합니다.
                for rule in security_group['IpPermissions']:
                    # 보안 그룹이 포트 6379에서 모든 IP 주소(0.0.0.0/0)로부터의 인바운드 트래픽을 허용하는지 확인합니다.
                    if rule.get('FromPort') == 6379 and rule.get('ToPort') == 6379:
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                is_redis_exposed = True
                                break
                        
                        if is_redis_exposed:
                            break
                
                if is_redis_exposed:
                    break
            
            # Redis 포트가 인터넷에 노출된 경우와 그렇지 않은 경우의 상태와 심각도를 설정합니다.
            if is_redis_exposed:
                status = "FAIL"
                severity = "CRITICAL" if public_ip else "HIGH"
                status_extended = f"인스턴스 {instance_id}에 Redisport 6379가 인터넷에 열려 있습니다."
            else:
                status = "PASS"
                severity = "INFO"
                status_extended = f"인스턴스 {instance_id}에 인터넷에 열려 있는 Redisport 6379가 없습니다."
            
            # 점검 결과를 findings 리스트에 추가합니다.
            finding = {
                'arn': instance_arn,
                'tag': [{t['Key']: t['Value']} for t in instance.get('Tags', [])],
                'region': instance['Placement']['AvailabilityZone'][:-1],
                'policy_name': '',
                'status': status,
                'status_extended': status_extended,
                # 'severity': severity
            }
            findings.append(finding)

    return findings

# 점검 결과를 JSON 파일로 저장하는 함수입니다.
def save_findings_to_json(findings, filename):
    # 결과를 JSON 파일로 저장
    with open(filename, 'w',encoding='UTF-8-sig') as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)
        
if __name__ == '__main__':
    ec2_client = boto3.client('ec2')
    result = check_ec2_instance_port_redis_exposed_to_internet(ec2_client)
    save_findings_to_json(result, "ec2_instance_port_redis_exposed_to_internet.json")
    print("Results saved to 'ec2_instance_port_redis_exposed_to_internet.json'")
