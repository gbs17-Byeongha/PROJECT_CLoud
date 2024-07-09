import json
import boto3
from ipaddress import ip_network

def check_ec2_instance_port_kerberos_exposed_to_internet(ec2_client):
    '''
    Kerberos 포트(88, 464, 749, 750)가 인터넷에 노출되어 있는지를 점검

    공용 IP를 가지고 있는지, 서브넷이 공용 서브넷인지, 그리고 보안 그룹 규칙이 Kerberos 포트를 인터넷에 노출시키고 있는지를 확인
    '''
    findings = []
    kerberos_ports = [88, 464, 749, 750]  # Kerberos 포트 목록

    # 모든 EC2 인스턴스 가져오기
    instances = ec2_client.describe_instances()
    
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            # 인스턴스 ARN 생성 (AWS 리소스 식별자)
            instance_arn = f"arn:aws:ec2:{ec2_client.meta.region_name}:{ec2_client.describe_security_groups()['SecurityGroups'][0]['OwnerId']}:instance/{instance_id}"

            # 인스턴스에 공용 IP가 있는지 확인
            public_ip = instance.get('PublicIpAddress')
            
            # 서브넷 정보 가져오기
            subnet_id = instance['SubnetId']
            subnet = ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
            is_public_subnet = subnet['MapPublicIpOnLaunch']  # 서브넷이 공용 서브넷인지 확인

            # 보안 그룹 확인
            security_groups = instance['SecurityGroups']
            is_kerberos_exposed = False

            for sg in security_groups:
                sg_id = sg['GroupId']
                # 보안 그룹 규칙 가져오기
                sg_rules = ec2_client.describe_security_group_rules(Filters=[{'Name': 'group-id', 'Values': [sg_id]}])

                for rule in sg_rules['SecurityGroupRules']:
                    if rule.get('IsEgress', True):  # 아웃바운드 규칙은 무시
                        continue
                    
                    from_port = rule.get('FromPort')
                    to_port = rule.get('ToPort')
                    ip_protocol = rule.get('IpProtocol')
                    
                    # Kerberos 포트가 인터넷에 노출되어 있는지 확인
                    if ip_protocol == '-1' or (from_port <= min(kerberos_ports) and to_port >= max(kerberos_ports)):
                        cidr_ipv4 = rule.get('CidrIpv4')
                        if cidr_ipv4 and ip_network(cidr_ipv4).is_global:  # 글로벌 IP 범위인지 확인
                            is_kerberos_exposed = True
                            break
                
                if is_kerberos_exposed:
                    break

            if is_kerberos_exposed:
                if public_ip and is_public_subnet:
                    severity = "CRITICAL"  # 공용 IP와 공용 서브넷이면 심각
                elif public_ip:
                    severity = "HIGH"  # 공용 IP만 있으면 높음
                else:
                    severity = "MEDIUM"  # 공용 IP가 없으면 중간
                
                status = "FAIL"
                status_extended = f"인스턴스 {instance_id}에 인터넷에 Kerberos 포트가 열려 있습니다."
            else:
                status = "PASS"
                status_extended = f"인스턴스 {instance_id}에 인터넷에 열려 있는 Kerberos 포트가 없습니다."
                severity = "INFO"

            finding = {
                'arn': instance_arn,
                'tag': [{t['Key']: t['Value']} for t in instance.get('Tags', [])],  # 인스턴스 태그
                'region': ec2_client.meta.region_name,
                'policy_name': '',
                'status': status,
                'status_extended': status_extended,
                # 'severity': severity  # 심각도 (주석 처리됨)
            }
            findings.append(finding)

    return findings

def save_findings_to_json(findings, filename):
    # 결과를 JSON 파일로 저장
    with open(filename, 'w',encoding='UTF-8-sig') as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)

if __name__ == '__main__':
    ec2_client = boto3.client('ec2')
    result = check_ec2_instance_port_kerberos_exposed_to_internet(ec2_client)
    save_findings_to_json(result, "ec2_instance_port_kerberos_exposed_to_internet.json")
    print("Results saved to 'ec2_instance_port_kerberos_exposed_to_internet.json'")
