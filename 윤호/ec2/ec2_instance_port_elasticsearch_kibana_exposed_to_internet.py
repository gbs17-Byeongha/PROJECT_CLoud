import json
import boto3

def check_ec2_instance_port_elasticsearch_kibana_exposed_to_internet(ec2_client):
    """
    EC2 인스턴스의 Elasticsearch 및 Kibana 포트(TCP 9200, 9300, 5601)가 인터넷에 노출되어 있는지 확인합니다.
    이를 통해 잠재적인 보안 위험을 식별하고 데이터 노출을 방지할 수 있습니다.
    """
    findings = []
    check_ports = [9200, 9300, 5601]  # 확인할 포트 목록

    # 모든 EC2 인스턴스 가져오기
    instances = ec2_client.describe_instances()['Reservations']

    for reservation in instances:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_arn = f"arn:aws:ec2:{ec2_client.meta.region_name}:{ec2_client.describe_security_groups()['SecurityGroups'][0]['OwnerId']}:instance/{instance_id}"
            
            # 보안 그룹 확인
            security_groups = instance.get('SecurityGroups', [])
            is_open_port = False

            for sg in security_groups:
                sg_id = sg['GroupId']
                # 보안 그룹의 규칙을 가져옴
                sg_rules = ec2_client.describe_security_group_rules(Filters=[{'Name': 'group-id', 'Values': [sg_id]}])['SecurityGroupRules']

                for rule in sg_rules:
                    # 인바운드 규칙만 확인
                    if rule.get('IsEgress', True) == False:
                        # TCP 프로토콜이면서 확인할 포트(9200, 9300, 5601)에 해당하는지 확인
                        if rule.get('IpProtocol') == 'tcp' and rule.get('FromPort') in check_ports and rule.get('ToPort') in check_ports:
                            # 0.0.0.0/0은 모든 IP 주소를 의미, 즉 인터넷에 공개된 경우
                            if rule.get('CidrIpv4') == '0.0.0.0/0':
                                is_open_port = True
                                break

                if is_open_port:
                    break

            status = "FAIL" if is_open_port else "PASS"
            severity = "CRITICAL"

            if is_open_port:
                # 인스턴스가 공용 서브넷에 있는지 확인
                subnet_id = instance.get('SubnetId')
                subnet = ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
                route_table_id = ec2_client.describe_route_tables(Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}])['RouteTables'][0]['RouteTableId']
                routes = ec2_client.describe_route_tables(RouteTableIds=[route_table_id])['RouteTables'][0]['Routes']

                # 인터넷 게이트웨이(igw-)가 있는지 확인하여 공용 서브넷인지 판단
                is_public_subnet = any(route.get('GatewayId', '').startswith('igw-') for route in routes)

                # 공용 서브넷이면서 퍼블릭 IP가 있는 경우, 심각도 설정
                if is_public_subnet and instance.get('PublicIpAddress'):
                    severity = "CRITICAL"
                elif instance.get('PublicIpAddress'):
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"

            status_extended = f"인스턴스 {instance_id}에 인터넷에 열려 있는 Elasticsearch/Kibana 포트가{'있습니다.' if is_open_port else '없습니다.'}"

            # 결과 저장
            finding = {
                'arn': instance_arn,
                'tag': [{t['Key']: t['Value']} for t in instance.get('Tags', [])],
                'region': ec2_client.meta.region_name,
                'policy_name': '',  # 정책 이름은 해당되지 않음
                'status': status,
                'status_extended': status_extended,
                # 'severity': severity  # 심각도는 필요시 추가 가능
            }
            findings.append(finding)

    return findings

def save_findings_to_json(findings, filename):
    # 결과를 JSON 파일로 저장
    with open(filename, 'w',encoding='UTF-8-sig') as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)

# 결과 실행 및 출력
if __name__ == '__main__':
    ec2_client = boto3.client('ec2')
    result = check_ec2_instance_port_elasticsearch_kibana_exposed_to_internet(ec2_client)
    save_findings_to_json(result, "ec2_instance_port_elasticsearch_kibana_exposed_to_internet.json")
    print("Results saved to 'ec2_instance_port_elasticsearch_kibana_exposed_to_internet.json'")
