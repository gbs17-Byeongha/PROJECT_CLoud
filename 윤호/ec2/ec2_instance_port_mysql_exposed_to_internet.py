import json
import boto3

def check_ec2_instance_port_mysql_exposed_to_internet(ec2_client):
    '''
    MySQL 포트(3306)가 인터넷에 노출되어 있는지 확인
    '''
    findings = []

    # 모든 EC2 인스턴스 가져오기
    instances = ec2_client.describe_instances()

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            owner_id = instance.get('OwnerId', 'unknown-owner')
            instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{owner_id}:instance/{instance_id}"

            # 인스턴스에 연결된 보안 그룹 확인
            security_groups = instance['SecurityGroups']
            is_mysql_open = False

            for sg in security_groups:
                security_group = ec2_client.describe_security_groups(GroupIds=[sg['GroupId']])['SecurityGroups'][0]
                
                # 인바운드 규칙 확인
                for rule in security_group['IpPermissions']:
                    # 포트 3306이 인터넷에 열려 있는지 확인 (0.0.0.0/0)
                    if rule.get('FromPort', 0) <= 3306 <= rule.get('ToPort', 65535):
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                is_mysql_open = True
                                break
                    if is_mysql_open:
                        break
                if is_mysql_open:
                    break

            if is_mysql_open:
                status = 'FAIL'
                status_extended = f"인스턴스 {instance_id}에 MySQL 포트 3306이 인터넷에 열려 있습니다."
            else:
                status = 'PASS'
                status_extended = f"인스턴스 {instance_id}에 인터넷에 열려 있는 MySQL 포트 3306이 없습니다."

            finding = {
                'arn': instance_arn,
                'tag': [{t['Key']: t['Value']} for t in instance.get('Tags', [])] if 'Tags' in instance else '',
                'region': instance['Placement']['AvailabilityZone'][:-1],
                'policy_name': '',  # EC2 인스턴스에는 해당 없음
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
    result = check_ec2_instance_port_mysql_exposed_to_internet(ec2_client)
    save_findings_to_json(result, "ec2_instance_port_mysql_exposed_to_internet.json")
    print("Results saved to 'ec2_instance_port_mysql_exposed_to_internet.json'")
