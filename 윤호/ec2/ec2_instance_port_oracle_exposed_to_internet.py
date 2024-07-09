import json
import boto3

def check_ec2_instance_port_oracle_exposed_to_internet(ec2_client):
    '''
    Oracle 관련 포트 (1521, 2483, 2484)가 인터넷에 노출되어 있는지 점검
    '''
    findings = []
    check_ports = [1521, 2483, 2484]  # 점검할 Oracle 관련 포트 목록

    # 모든 EC2 인스턴스 가져오기
    instances = ec2_client.describe_instances()
    
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_arn = f"arn:aws:ec2:{ec2_client.meta.region_name}:{ec2_client.describe_security_groups()['SecurityGroups'][0]['OwnerId']}:instance/{instance_id}"
            
            # 보안 그룹 확인
            security_groups = instance.get('SecurityGroups', [])
            is_open_port = False

            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_rules = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]

                for rule in sg_rules['IpPermissions']:
                    # 지정된 포트가 0.0.0.0/0 (모든 IP)로 공개되어 있는지 확인
                    if rule.get('FromPort') in check_ports and rule.get('ToPort') in check_ports:
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                is_open_port = True
                                break
                    if is_open_port:
                        break
                if is_open_port:
                    break

            if is_open_port:
                # 인스턴스의 서브넷 확인
                subnet_id = instance['SubnetId']
                subnet = ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
                is_public_subnet = subnet.get('MapPublicIpOnLaunch', False)

                # 공개 IP 확인
                public_ip = instance.get('PublicIpAddress')

                # 공개 IP 및 서브넷 여부에 따른 심각도 설정
                if public_ip and is_public_subnet:
                    severity = "CRITICAL"
                    status_extended = f"인스턴스 {instance_id}에 인터넷에 Oracle 포트가 열려 있고 공용 IP가 있으며 공용 서브넷에 있습니다."
                elif public_ip:
                    severity = "HIGH"
                    status_extended = f"인스턴스 {instance_id}에 인터넷에 오라클 포트가 열려 있고 공용 IP가 있지만 개인 서브넷에 있습니다."
                else:
                    severity = "MEDIUM"
                    status_extended = f"인스턴스 {instance_id}에 인터넷에 개방된 Oracle 포트가 있지만 공용 IP가 없습니다."

                status = "FAIL"
            else:
                status = "PASS"
                status_extended = f"인스턴스 {instance_id}에 인터넷에 열려 있는 Oracle 포트가 없습니다."
                severity = "INFO"

            # 점검 결과 구성
            finding = {
                'arn': instance_arn,
                'tag': [{t['Key']: t['Value']} for t in instance.get('Tags', [])],
                'region': ec2_client.meta.region_name,
                'policy_name': '',
                'status': status,
                'status_extended': status_extended,
                # 'severity': severity  # 필요에 따라 심각도 추가 가능
            }
            findings.append(finding)

    return findings

def save_findings_to_json(findings, filename):
    # 결과를 JSON 파일로 저장
    with open(filename, 'w',encoding='UTF-8-sig') as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)

if __name__ == '__main__':
    ec2_client = boto3.client('ec2')
    result = check_ec2_instance_port_oracle_exposed_to_internet(ec2_client)
    save_findings_to_json(result, "ec2_instance_port_oracle_exposed_to_internet.json")
    print("Results saved to 'ec2_instance_port_oracle_exposed_to_internet.json'")
