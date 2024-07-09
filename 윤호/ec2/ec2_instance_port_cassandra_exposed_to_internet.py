import json
import boto3

def check_ec2_instance_port_cassandra_exposed_to_internet(ec2_client):
    """
    EC2 인스턴스의 Cassandra 포트(TCP 7000, 7001, 7199, 9042, 9160)가 인터넷에 노출되어 있는지 확인합니다.
    각 인스턴스의 보안 그룹 규칙을 검사하여 해당 포트들이 '0.0.0.0/0' (인터넷 전체)에 대해 열려 있는지 체크하고, 인스턴스가 퍼블릭 서브넷에 있는지, 퍼블릭 IP를 가지고 있는지 등을 확인합니다.
    """
    findings = []
    check_ports = [7000, 7001, 7199, 9042, 9160]

    # 모든 EC2 인스턴스 가져오기
    instances = ec2_client.describe_instances()

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_arn = f"arn:aws:ec2:{ec2_client.meta.region_name}:{ec2_client.describe_security_groups()['SecurityGroups'][0]['OwnerId']}:instance/{instance_id}"
            
            # 인스턴스의 보안 그룹 확인
            security_groups = instance.get('SecurityGroups', [])
            is_open_port = False

            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_resource = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]

                for rule in sg_resource['IpPermissions']:
                    # Cassandra 포트가 열려있는지 확인
                    if rule.get('FromPort') in check_ports and rule.get('ToPort') in check_ports:
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':  # 인터넷에 노출 여부 확인
                                is_open_port = True
                                break
                    if is_open_port:
                        break
                if is_open_port:
                    break

            # 인스턴스의 공개 IP 및 서브넷 상태 확인
            public_ip = instance.get('PublicIpAddress')
            subnet_id = instance.get('SubnetId')
            subnet = ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
            is_public_subnet = subnet['MapPublicIpOnLaunch']

            # 인스턴스의 상태 평가
            if is_open_port:
                if public_ip and is_public_subnet:
                    status = "FAIL"
                    severity = "CRITICAL"
                    status_extended = f"인스턴스 {instance_id}에 Cassandra 포트가 인터넷에 열려 있고 공용 IP가 있는 공용 서브넷에 있습니다."
                elif public_ip:
                    status = "FAIL"
                    severity = "HIGH"
                    status_extended = f"인스턴스 {instance_id}에 Cassandra 포트가 인터넷에 열려 있고 공용 IP가 있지만 개인 서브넷에 있습니다."
                else:
                    status = "FAIL"
                    severity = "MEDIUM"
                    status_extended = f"인스턴스 {instance_id}에 Cassandra 포트가 인터넷에 열려 있지만 공용 IP가 없습니다."
            else:
                status = "PASS"
                severity = "INFO"
                status_extended = f"인스턴스 {instance_id}에 인터넷에 열려 있는 Cassandra 포트가 없습니다."

            finding = {
                'ResourceId': instance_id,
                'ResourceArn': instance_arn,
                'Region': ec2_client.meta.region_name,
                'Tags': [{t['Key']: t['Value']} for t in instance.get('Tags', [])],
                'Status': status,
                'StatusExtended': status_extended,
                'Severity': severity
            }
            findings.append(finding)

    # 결과를 JSON 형식으로 정리
    results = []
    for finding in findings:
        result = {
            'arn': finding['ResourceArn'],
            'tag': finding['Tags'],
            'region': finding['Region'],
            'policy_name': '',  # Policy name is not applicable
            'status': finding['Status'],
            'status_extended': finding['StatusExtended']
        }
        results.append(result)

    return results

def save_findings_to_json(findings, filename):
    # 결과를 JSON 파일로 저장
    with open(filename, 'w',encoding='UTF-8-sig') as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)

# 결과 실행 및 출력
if __name__ == '__main__':
    ec2_client = boto3.client('ec2')
    result = check_ec2_instance_port_cassandra_exposed_to_internet(ec2_client)
    save_findings_to_json(result, "ec2_instance_port_cassandra_exposed_to_internet.json")
    print("Results saved to 'ec2_instance_port_cassandra_exposed_to_internet.json'")