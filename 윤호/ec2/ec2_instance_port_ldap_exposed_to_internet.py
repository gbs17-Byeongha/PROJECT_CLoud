import json
import boto3

def check_ec2_instance_port_ldap_exposed_to_internet(ec2_client):
    '''
    LDAP 포트(389, 636)가 인터넷에 노출되어 있는지 점검
    '''
    findings = []
    check_ports = [389, 636]  # LDAP 포트 번호

    # 모든 EC2 인스턴스 가져오기
    instances = ec2_client.describe_instances()
    
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_arn = f"arn:aws:ec2:{ec2_client.meta.region_name}:{ec2_client.describe_security_groups()['SecurityGroups'][0]['OwnerId']}:instance/{instance_id}"
            
            # 인스턴스에 퍼블릭 IP가 있는지 확인
            has_public_ip = 'PublicIpAddress' in instance
            
            # 인스턴스의 보안 그룹 가져오기
            security_groups = instance.get('SecurityGroups', [])
            
            is_open_port = False  # 포트가 열려 있는지 여부
            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_details = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
                
                for rule in sg_details['IpPermissions']:
                    if rule.get('IpProtocol') == 'tcp':
                        from_port = rule.get('FromPort')
                        to_port = rule.get('ToPort')
                        
                        # LDAP 포트가 열려 있는지 확인
                        if from_port <= min(check_ports) and to_port >= max(check_ports):
                            for ip_range in rule.get('IpRanges', []):
                                if ip_range.get('CidrIp') == '0.0.0.0/0':  # 인터넷에 공개되어 있는지 확인
                                    is_open_port = True
                                    break
                            
                            if is_open_port:
                                break
                
                if is_open_port:
                    break
            
            # 서브넷의 공용/사설 여부 확인
            subnet_id = instance.get('SubnetId')
            subnet = ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
            is_public_subnet = subnet.get('MapPublicIpOnLaunch', False)

            # 결과에 따른 상태 및 심각도 설정
            if is_open_port:
                status = "FAIL"
                if has_public_ip and is_public_subnet:
                    severity = "CRITICAL"
                    status_extended = f"인스턴스 {instance_id}에 인터넷에 LDAP 포트가 열려 있고 공용 IP가 있으며 공용 서브넷에 있습니다."
                elif has_public_ip:
                    severity = "HIGH"
                    status_extended = f"인스턴스 {instance_id}에 인터넷에 LDAP 포트가 열려 있고 공용 IP가 있지만 개인 서브넷에 있습니다."
                else:
                    severity = "MEDIUM"
                    status_extended = f"인스턴스 {instance_id}에 인터넷에 LDAP 포트가 열려 있지만 공용 IP가 없습니다."
            else:
                status = "PASS"
                severity = "INFO"
                status_extended = f"인스턴스 {instance_id}에 인터넷에 열려 있는 LDAP 포트가 없습니다."

            # 점검 결과를 딕셔너리 형태로 저장
            finding = {
                'arn': instance_arn,
                'tag': [{t['Key']: t['Value']} for t in instance.get('Tags', [])],
                'region': ec2_client.meta.region_name,
                'policy_name': '',
                'status': status,
                'status_extended': status_extended,
                # 'severity': severity  # 필요에 따라 주석 해제 가능
            }
            findings.append(finding)

    return findings

def save_findings_to_json(findings, filename):
    # 결과를 JSON 파일로 저장
    with open(filename, 'w',encoding='UTF-8-sig') as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)

if __name__ == '__main__':
    # AWS EC2 클라이언트 생성
    ec2_client = boto3.client('ec2')
    # LDAP 포트가 인터넷에 노출되어 있는지 점검
    result = check_ec2_instance_port_ldap_exposed_to_internet(ec2_client)
    # 점검 결과를 JSON 파일로 저장
    save_findings_to_json(result, "ec2_instance_port_ldap_exposed_to_internet.json")
    print("Results saved to 'ec2_instance_port_ldap_exposed_to_internet.json'")
