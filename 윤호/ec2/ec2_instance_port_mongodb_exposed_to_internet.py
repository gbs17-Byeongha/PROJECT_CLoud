import json
import boto3

def check_ec2_instance_port_mongodb_exposed_to_internet(ec2_client):
    '''
    MongoDB 포트(27017, 27018)가 인터넷에 노출되어 있는지를 확인
    '''
    findings = []
    check_ports = [27017, 27018]  # MongoDB 포트

    # 모든 EC2 인스턴스를 조회
    instances = ec2_client.describe_instances()

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            owner_id = instance.get('OwnerId', 'unknown-owner')
            instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{owner_id}:instance/{instance_id}"
            region = instance['Placement']['AvailabilityZone'][:-1]
            tags = [{t['Key']: t['Value']} for t in instance.get('Tags', [])] if instance.get('Tags') else ''
            public_ip_address = instance.get('PublicIpAddress')
            subnet_id = instance['SubnetId']

            # 기본적으로 PASS 상태로 설정
            finding = {
                'resource_arn': instance_arn,
                'tag': tags,
                'region': region,
                'policy_name': '',
                'status': 'PASS',
                'status_extended': f"인스턴스 {instance_id}에 인터넷에 열려 있는 MongoDB 포트가 없습니다."
            }

            # 인스턴스에 연결된 보안 그룹 확인
            for sg in instance['SecurityGroups']:
                sg_id = sg['GroupId']
                security_group = ec2_client.describe_security_groups(GroupIds=[sg_id])

                # 보안 그룹의 모든 인바운드 규칙을 확인
                for rule in security_group['SecurityGroups'][0]['IpPermissions']:
                    if rule.get('IpProtocol') == 'tcp':
                        from_port = rule.get('FromPort', 0)
                        to_port = rule.get('ToPort', 65535)

                        # MongoDB 포트가 열려있는지 확인
                        if any(port in range(from_port, to_port + 1) for port in check_ports):
                            for ip_range in rule.get('IpRanges', []):
                                if ip_range.get('CidrIp') == '0.0.0.0/0':  # 인터넷에 공개된 경우
                                    finding['status'] = 'FAIL'

                                    # 인스턴스의 공개 접근 가능성을 기반으로 심각도 결정
                                    subnet = ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
                                    if public_ip_address:
                                        if subnet.get('MapPublicIpOnLaunch', False):
                                            severity = "CRITICAL"
                                        else:
                                            severity = "HIGH"
                                    else:
                                        severity = "MEDIUM"

                                    finding['status_extended'] = f"인스턴스 {instance_id}에 MongoDB 포트가 인터넷에 열려 있습니다. 심각도: {severity}"
                                    break  # 발견된 경우 반복 중지

                        if finding['status'] == 'FAIL':
                            break  # 발견된 경우 반복 중지

                if finding['status'] == 'FAIL':
                    break  # 발견된 경우 반복 중지

            findings.append(finding)

    return findings

def save_findings_to_json(findings, filename):
    # 결과를 JSON 파일로 저장
    with open(filename, 'w',encoding='UTF-8-sig') as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)

if __name__ == '__main__':
    ec2_client = boto3.client('ec2')
    
    result = check_ec2_instance_port_mongodb_exposed_to_internet(ec2_client)
    save_findings_to_json(result, "ec2_instance_port_mongodb_exposed_to_internet.json")
    print("Results saved to 'ec2_instance_port_mongodb_exposed_to_internet.json'")
