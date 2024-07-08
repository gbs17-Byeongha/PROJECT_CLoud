import json
import boto3

def check_ec2_instance_port_sqlserver_exposed_to_internet(ec2_client):
    '''
    SQL Server 포트(1433, 1434)가 인터넷에 노출되어 있는지 점검
    '''
    findings = []

    # EC2 인스턴스 정보 가져오기
    instances = ec2_client.describe_instances()
    
    # VPC 서브넷 정보 가져오기
    subnets = ec2_client.describe_subnets()
    subnet_dict = {subnet['SubnetId']: subnet for subnet in subnets['Subnets']}
    
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_arn = f"arn:aws:ec2:{ec2_client.meta.region_name}:{ec2_client.describe_security_groups()['SecurityGroups'][0]['OwnerId']}:instance/{instance_id}"
            
            # 보안 그룹 점검
            security_groups = instance.get('SecurityGroups', [])
            is_exposed = False
            for sg in security_groups:
                sg_details = ec2_client.describe_security_groups(GroupIds=[sg['GroupId']])
                for sg_detail in sg_details['SecurityGroups']:
                    for rule in sg_detail.get('IpPermissions', []):
                        # SQL Server 포트가 인터넷에 열려 있는지 확인
                        if rule.get('IpProtocol') == 'tcp' and rule.get('FromPort') in [1433, 1434]:
                            for ip_range in rule.get('IpRanges', []):
                                if ip_range.get('CidrIp') == '0.0.0.0/0':
                                    is_exposed = True
                                    break
                    if is_exposed:
                        break
                if is_exposed:
                    break

            # 인스턴스의 공개 상태 확인
            public_ip = instance.get('PublicIpAddress')
            subnet_id = instance.get('SubnetId')
            is_public_subnet = subnet_dict[subnet_id]['MapPublicIpOnLaunch'] if subnet_id in subnet_dict else False

            if is_exposed:
                if public_ip and is_public_subnet:
                    status = "FAIL"
                    severity = "CRITICAL"
                    status_extended = f"Instance {instance_id} has SQL Server ports open to the Internet and is in a public subnet with a public IP."
                elif public_ip:
                    status = "FAIL"
                    severity = "HIGH"
                    status_extended = f"Instance {instance_id} has SQL Server ports open to the Internet and has a public IP but is in a private subnet."
                else:
                    status = "FAIL"
                    severity = "MEDIUM"
                    status_extended = f"Instance {instance_id} has SQL Server ports open to the Internet but has no public IP."
            else:
                status = "PASS"
                severity = "INFO"
                status_extended = f"Instance {instance_id} does not have SQL Server ports open to the Internet."

            finding = {
                'arn': instance_arn,
                'tag': [{t['Key']: t['Value']} for t in instance.get('Tags', [])],
                'region': ec2_client.meta.region_name,
                'policy_name': '',  # Not applicable for EC2 instances
                'status': status,
                'status_extended': status_extended,
                # 'severity': severity  # 주석 처리된 부분
            }
            findings.append(finding)

    return findings

def save_findings_to_json(findings, filename):
    with open(filename, 'w') as file:
        json.dump(findings, file, indent=4)

if __name__ == '__main__':
    ec2_client = boto3.client('ec2')
    result = check_ec2_instance_port_sqlserver_exposed_to_internet(ec2_client)
    save_findings_to_json(result, "ec2_instance_port_sqlserver_exposed_to_internet.json")
    print("Results saved to 'ec2_instance_port_sqlserver_exposed_to_internet.json'")
