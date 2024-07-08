import json
import boto3

def check_ec2_instance_port_memcached_exposed_to_internet(ec2_client):
    '''
    Memcached 포트(11211)가 인터넷에 노출되어 있는지 점검
    '''
    findings = []
    check_port = 11211

    # 모든 EC2 인스턴스를 조회
    instances = ec2_client.describe_instances()

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_arn = f"arn:aws:ec2:{ec2_client.meta.region_name}:{ec2_client.describe_security_groups()['SecurityGroups'][0]['OwnerId']}:instance/{instance_id}"
            
            # 점검 결과 초기화
            finding = {
                'arn': instance_arn,
                'tag': [{t['Key']: t['Value']} for t in instance.get('Tags', [])],
                'region': ec2_client.meta.region_name,
                'policy_name': '',
                'status': 'PASS',
                'status_extended': f"Instance {instance_id} does not have Memcached port 11211 open to the Internet."
            }

            # 보안 그룹 확인
            for sg in instance['SecurityGroups']:
                sg_id = sg['GroupId']
                sg_rules = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]['IpPermissions']
                
                for rule in sg_rules:
                    # Memcached 포트(11211)이 열려 있는지 확인
                    if rule.get('FromPort') == check_port and rule.get('ToPort') == check_port and rule.get('IpProtocol') == 'tcp':
                        for ip_range in rule.get('IpRanges', []):
                            # 포트가 0.0.0.0/0 (인터넷)에 열려 있는지 확인
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                finding['status'] = 'FAIL'
                                
                                # 인스턴스가 공용 서브넷에 있는지와 공용 IP가 있는지 확인
                                subnet_id = instance['SubnetId']
                                subnet = ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
                                is_public_subnet = subnet['MapPublicIpOnLaunch']
                                has_public_ip = 'PublicIpAddress' in instance
                                
                                if has_public_ip and is_public_subnet:
                                    finding['status_extended'] = f"Instance {instance_id} has Memcached port 11211 open to the Internet and is in a public subnet with a public IP."
                                elif has_public_ip:
                                    finding['status_extended'] = f"Instance {instance_id} has Memcached port 11211 open to the Internet and has a public IP but is in a private subnet."
                                else:
                                    finding['status_extended'] = f"Instance {instance_id} has Memcached port 11211 open to the Internet but has no public IP."
                                
                                break
                        
                        if finding['status'] == 'FAIL':
                            break
                
                if finding['status'] == 'FAIL':
                    break

            findings.append(finding)

    return findings

def save_findings_to_json(findings, filename):
    # 점검 결과를 JSON 파일로 저장
    with open(filename, 'w') as file:
        json.dump(findings, file, indent=4)

if __name__ == '__main__':
    ec2_client = boto3.client('ec2')
    result = check_ec2_instance_port_memcached_exposed_to_internet(ec2_client)
    save_findings_to_json(result, "ec2_instance_port_memcached_exposed_to_internet.json")
    print("Results saved to 'ec2_instance_port_memcached_exposed_to_internet.json'")
