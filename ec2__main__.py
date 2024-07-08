import json
import boto3
import os
from botocore.exceptions import NoCredentialsError, ClientError

# 각 기능 모듈에서 함수들을 가져옴
from ec2_instance_port_ssh_exposed_to_internet import ec2_instance_port_ssh_exposed_to_internet2
from ec2_instance_port_telnet_exposed_to_internet import ec2_instance_port_telnet_exposed_to_internet2
from ec2_instance_profile_attached import ec2_instance_profile_attached2
from ec2_instance_public_ip import ec2_instance_public_ip2
from ec2_instance_secrets_user_data import ec2_instance_secrets_user_data2
from ec2_launch_template_no_secrets import ec2_launch_template_no_secrets2
from ec2_networkacl_allow_ingress_any_port import ec2_networkacl_allow_ingress_any_port2
from ec2_networkacl_allow_ingress_tcp_port_22 import ec2_networkacl_allow_ingress_tcp_port_22_1
from ec2_securitygroup_allow_ingress_from_internet_to_all_ports import ec2_networkacl_allow_ingress_tcp_port_3389_1
from ec2_securitygroup_allow_ingress_from_internet_to_any_port import ec2_securitygroup_allow_ingress_from_internet_to_any_port_2
from ec2_securitygroup_allow_ingress_from_internet_to_port_mongodb_27017_27018 import ec2_securitygroup_allow_ingress_from_internet_to_mongodb_ports
from ec2_securitygroup_allow_ingress_from_internet_to_tcp_ftp_port_20_21 import ec2_securitygroup_allow_ingress_from_internet_to_ftp_ports
from ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22 import ec2_securitygroup_allow_ingress_from_internet_to_ssh_port_22
from ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389 import ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389_2
from lib import *

# 정사각형 테두리 생성 함수
def print_in_box(lines):
    # 가장 긴 문자열의 길이를 구함
    max_length = max(len(f"{index + 1}. {line}") for index, line in enumerate(lines))
    # 테두리의 윗부분 출력
    print('╔' + '═' * (max_length + 2) + '╗')
    for index, line in enumerate(lines):
        # 각 줄의 내용을 테두리 안에 맞게 출력
        print(f'║ {index + 1}. {line.ljust(max_length - len(f"{index + 1}. "))} ║')
    # 테두리의 아랫부분 출력
    print('╚' + '═' * (max_length + 2) + '╝')

# EC2 인스턴스 목록 가져오기 함수
def list_ec2_instances(ec2_resource):
    instances = []
    # 모든 EC2 인스턴스를 반복하면서 ID를 리스트에 추가
    for instance in ec2_resource.instances.all():
        instances.append(instance.id)
    return instances

# 사용자로부터 분석할 EC2 인스턴스 선택 함수
def ec2_client_info(ec2_resource):
    # EC2 인스턴스 목록 가져오기
    instance_ids = list_ec2_instances(ec2_resource)
    print("Select the EC2 instances you want to analyze:\n")
    print("0. All instances")
    # 인스턴스 목록을 박스 형태로 출력
    print_in_box(instance_ids)
    while True:
        try:
            # 사용자로부터 선택 입력 받기
            selection = int(input("Enter the number: "))
            if selection == 0:
                # 0을 선택하면 모든 인스턴스를 선택
                selected_instances = instance_ids
                break
            elif 1 <= selection <= len(instance_ids):
                # 해당 번호의 인스턴스를 선택
                selected_instances = [instance_ids[selection - 1]]
                break
            else:
                print("Please enter a valid number.")
        except ValueError:
            print("Please enter a number.")

    print(f"Selected EC2 instances: {', '.join(selected_instances)}")
    return selected_instances

# EC2 클라이언트 및 리소스 생성 함수
def create_ec2_client_and_resource():
    while True:
        try:
            # 환경 변수에서 AWS 자격 증명 가져오기
            aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
            aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')

            if not aws_access_key_id or not aws_secret_access_key:
                raise NoCredentialsError

            # EC2 클라이언트 및 리소스 생성
            ec2_client = boto3.client(
                'ec2',
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key
            )
            ec2_resource = boto3.resource(
                'ec2',
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key
            )
            # 자격 증명이 유효한지 확인
            ec2_client.describe_instances()
            return ec2_client, ec2_resource
        except (NoCredentialsError, ClientError):
            print("Invalid AWS credentials. Please enter your AWS credentials.")
            # 사용자로부터 AWS 자격 증명 입력 받기
            aws_access_key_id = input("AWS Access Key ID: ")
            aws_secret_access_key = input("AWS Secret Access Key: ")

            # 환경 변수에 자격 증명 저장
            os.environ['AWS_ACCESS_KEY_ID'] = aws_access_key_id
            os.environ['AWS_SECRET_ACCESS_KEY'] = aws_secret_access_key

            # 자격 증명을 파일에 저장
            config_data = {
                "AWS_ACCESS_KEY_ID": aws_access_key_id,
                "AWS_SECRET_ACCESS_KEY": aws_secret_access_key
            }

            with open('config.json', 'w') as config_file:
                json.dump(config_data, config_file, indent=4)

            try:
                # 입력 받은 자격 증명으로 다시 클라이언트 및 리소스 생성
                ec2_client = boto3.client(
                    'ec2',
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key
                )
                ec2_resource = boto3.resource(
                    'ec2',
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key
                )
                # 자격 증명이 유효한지 다시 확인
                ec2_client.describe_instances()
                return ec2_client, ec2_resource
            except ClientError as e:
                print(f"Error: {e}")
                print("The provided credentials are invalid. Please try again.")

# 메인 함수
if __name__ == "__main__":
    # config.json 파일이 있는지 확인
    if os.path.exists('config.json'):
        with open('config.json', 'r') as config_file:
            config_data = json.load(config_file)
            os.environ['AWS_ACCESS_KEY_ID'] = config_data['AWS_ACCESS_KEY_ID']
            os.environ['AWS_SECRET_ACCESS_KEY'] = config_data['AWS_SECRET_ACCESS_KEY']

    # EC2 클라이언트 및 리소스 생성
    ec2_client, ec2_resource = create_ec2_client_and_resource()
    # 분석할 EC2 인스턴스 선택
    selected_instances = ec2_client_info(ec2_resource)
    results = {}

    # 선택된 각 인스턴스에 대해 분석 수행
    for instance_id in selected_instances:
        results[instance_id] = {}

        # 각 함수 호출하여 결과 저장
        ssh_exposed = ec2_instance_port_ssh_exposed_to_internet2(ec2_resource)
        telnet_exposed = ec2_instance_port_telnet_exposed_to_internet2(ec2_client)
        profile_attached = ec2_instance_profile_attached2(ec2_client)
        public_ip = ec2_instance_public_ip2(ec2_client)
        secrets_user_data = ec2_instance_secrets_user_data2(ec2_client)
        launch_template_secrets = ec2_launch_template_no_secrets2(ec2_client)
        n_acl_ingress_any_port = ec2_networkacl_allow_ingress_any_port2(ec2_client)
        n_acl_ingress_tcp_22 = ec2_networkacl_allow_ingress_tcp_port_22_1(ec2_client)
        sg_all_ports_open = ec2_networkacl_allow_ingress_tcp_port_3389_1(ec2_client)
        sg_ingress_any_port = ec2_securitygroup_allow_ingress_from_internet_to_any_port_2(ec2_client)
        sg_ingress_mongodb_ports = ec2_securitygroup_allow_ingress_from_internet_to_mongodb_ports(ec2_client)
        sg_ingress_ftp_ports = ec2_securitygroup_allow_ingress_from_internet_to_ftp_ports(ec2_client)
        sg_ingress_ssh_22 = ec2_securitygroup_allow_ingress_from_internet_to_ssh_port_22(ec2_client)
        sg_ingress_tcp_3389 = ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389_2(ec2_client)

        # 결과를 딕셔너리에 저장
        results[instance_id] = {
            'ssh_exposed': ssh_exposed,
            'telnet_exposed': telnet_exposed,
            'profile_attached': profile_attached,
            'public_ip': public_ip,
            'secrets_user_data': secrets_user_data,
            'launch_template_secrets': launch_template_secrets,
            'n_acl_ingress_any_port': n_acl_ingress_any_port,
            'n_acl_ingress_tcp_22': n_acl_ingress_tcp_22,
            'sg_all_ports_open': sg_all_ports_open,
            'sg_ingress_any_port': sg_ingress_any_port,
            'sg_ingress_mongodb_ports': sg_ingress_mongodb_ports,
            'sg_ingress_ftp_ports': sg_ingress_ftp_ports,
            'sg_ingress_ssh_22': sg_ingress_ssh_22,
            'sg_ingress_tcp_3389': sg_ingress_tcp_3389
        }

    # 결과를 JSON 파일로 저장
    with open('ec2_analysis_results.json', 'w') as json_file:
        json.dump(results, json_file, indent=4)

    print("Results have been saved to ec2_analysis_results.json")
