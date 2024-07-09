import json
import boto3

def check_ec2_instance_port_kafka_exposed_to_internet(ec2_client):
    '''
    Kafka 포트(포트 번호 9092)가 인터넷에 노출되어 있는지 확인
    '''
    
    findings = []

    # 모든 EC2 인스턴스 가져오기
    instances = ec2_client.describe_instances()
    

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_arn = f"arn:aws:ec2:{ec2_client.meta.region_name}:{ec2_client.describe_security_groups()['SecurityGroups'][0]['OwnerId']}:instance/{instance_id}"
            
            # 인스턴스에 퍼블릭 IP가 있는지 확인
            has_public_ip = 'PublicIpAddress' in instance
            
            # 인스턴스가 퍼블릭 서브넷에 있는지 확인
            subnet_id = instance['SubnetId']
            subnet = ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
            is_public_subnet = subnet['MapPublicIpOnLaunch']

            # 보안 그룹 확인
            security_groups = instance['SecurityGroups']
            is_kafka_open = False

            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_rules = ec2_client.describe_security_group_rules(Filters=[{'Name': 'group-id', 'Values': [sg_id]}])

                for rule in sg_rules['SecurityGroupRules']:
                    # Kafka 포트 9092가 인터넷에 노출되어 있는지 확인
                    if rule.get('IsEgress') == False and rule.get('FromPort') == 9092 and rule.get('IpProtocol') == 'tcp' and rule.get('CidrIpv4') == '0.0.0.0/0':
                        is_kafka_open = True
                        break

                if is_kafka_open:
                    break

            if is_kafka_open:
                # 인스턴스가 퍼블릭 IP와 퍼블릭 서브넷에 있는 경우
                if has_public_ip and is_public_subnet:
                    severity = "CRITICAL"
                # 인스턴스가 퍼블릭 IP만 있는 경우
                elif has_public_ip:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"
                
                status = "FAIL"
                status_extended = f"인스턴스 {instance_id}에 인터넷에 Kafka 포트 9092가 열려 있습니다."
            else:
                status = "PASS"
                status_extended = f"인스턴스 {instance_id}에 인터넷에 열려 있는 Kafka 포트 9092가 없습니다."
                severity = "INFO"

            finding = {
                'arn': instance_arn,
                'tag': [{t['Key']: t['Value']} for t in instance.get('Tags', [])],
                'region': ec2_client.meta.region_name,
                'policy_name': '',
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
    result = check_ec2_instance_port_kafka_exposed_to_internet(ec2_client)
    save_findings_to_json(result, "ec2_instance_port_kafka_exposed_to_internet.json")
    print("Results saved to 'ec2_instance_port_kafka_exposed_to_internet.json'")
