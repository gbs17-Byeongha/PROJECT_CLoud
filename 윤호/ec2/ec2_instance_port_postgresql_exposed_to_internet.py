import json
import boto3

def check_ec2_instance_port_postgresql_exposed_to_internet(ec2_client):
    '''
    PostgreSQL 포트(5432)가 인터넷에 노출되어 있는지 확인
    '''
    findings = []

    # EC2 인스턴스 정보 가져오기
    instances = ec2_client.describe_instances()
    
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_arn = f"arn:aws:ec2:{ec2_client.meta.region_name}:{ec2_client.describe_security_groups()['SecurityGroups'][0]['OwnerId']}:instance/{instance_id}"
            
            # 보안 그룹 확인
            security_groups = instance.get('SecurityGroups', [])
            is_postgresql_open = False
            
            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_rules = ec2_client.describe_security_group_rules(Filters=[{'Name': 'group-id', 'Values': [sg_id]}])
                
                for rule in sg_rules['SecurityGroupRules']:
                    # PostgreSQL 포트 5432이 열려 있는지 확인
                    if rule.get('IpProtocol') == 'tcp' and rule.get('FromPort') <= 5432 <= rule.get('ToPort'):
                        cidr = rule.get('CidrIpv4')
                        if cidr == '0.0.0.0/0':  # 인터넷에 노출되는지 확인
                            is_postgresql_open = True
                            break
                
                if is_postgresql_open:
                    break
            
            # 인스턴스의 퍼블릭 IP와 서브넷 상태 확인
            public_ip = instance.get('PublicIpAddress')
            subnet_id = instance.get('SubnetId')
            subnet_info = ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
            is_public_subnet = subnet_info['MapPublicIpOnLaunch']

            if is_postgresql_open:
                if public_ip and is_public_subnet:
                    status = "FAIL"
                    severity = "CRITICAL"
                    status_extended = f"인스턴스 {instance_id}에 인터넷에 PostgreSQL 포트 5432가 열려 있고 공용 IP가 있는 공용 서브넷에 있습니다."
                elif public_ip:
                    status = "FAIL"
                    severity = "HIGH"
                    status_extended = f"인스턴스 {instance_id}에 인터넷에 PostgreSQL 포트 5432가 열려 있고 공용 IP가 있지만 개인 서브넷에 있습니다."
                else:
                    status = "FAIL"
                    severity = "MEDIUM"
                    status_extended = f"인스턴스 {instance_id}에 인터넷에 PostgreSQL 포트 5432가 열려 있지만 공용 IP가 없습니다."
            else:
                status = "PASS"
                severity = "INFO"
                status_extended = f"인스턴스 {instance_id}에 인터넷에 열려 있는 PostgreSQL 포트 5432가 없습니다."

            finding = {
                'arn': instance_arn,
                'tag': [{t['Key']: t['Value']} for t in instance.get('Tags', [])],
                'region': ec2_client.meta.region_name,
                'policy_name': '',  # 정책 이름은 해당 없음
                'status': status,
                'status_extended': status_extended,
                # 'severity': severity
            }
            findings.append(finding)

    return findings

def save_findings_to_json(findings, filename):
    # 결과를 JSON 파일로 저장
    with open(filename, 'w',encoding='UTF-8-sig') as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)

if __name__ == '__main__':
    ec2_client = boto3.client('ec2')
    result = check_ec2_instance_port_postgresql_exposed_to_internet(ec2_client)
    save_findings_to_json(result, "ec2_instance_port_postgresql_exposed_to_internet.json")
    print("Results saved to 'ec2_instance_port_postgresql_exposed_to_internet.json'")

