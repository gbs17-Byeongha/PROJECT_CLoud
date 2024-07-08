import json
import boto3

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

def main():
    findings = []
    
    ec2_client = boto3.client('ec2')
    ec2_resource = boto3.resource('ec2')

    # 각 함수 호출하여 결과 수집
    ssh_exposed_findings = ec2_instance_port_ssh_exposed_to_internet2(ec2_resource)
    for finding in ssh_exposed_findings:
        findings.append(finding)

    telnet_exposed_findings = ec2_instance_port_telnet_exposed_to_internet2(ec2_client)
    for finding in telnet_exposed_findings:
        findings.append(finding)

    profile_attached_findings = ec2_instance_profile_attached2(ec2_client)
    for finding in profile_attached_findings:
        findings.append(finding)

    public_ip_findings = ec2_instance_public_ip2(ec2_client)
    for finding in public_ip_findings:
        findings.append(finding)

    secrets_user_data_findings = ec2_instance_secrets_user_data2(ec2_client)
    for finding in secrets_user_data_findings:
        findings.append(finding)

    launch_template_secrets_findings = ec2_launch_template_no_secrets2(ec2_client)
    for finding in launch_template_secrets_findings:
        findings.append(finding)

    n_acl_ingress_any_port_findings = ec2_networkacl_allow_ingress_any_port2(ec2_client)
    for finding in n_acl_ingress_any_port_findings:
        findings.append(finding)

    n_acl_ingress_tcp_22_findings = ec2_networkacl_allow_ingress_tcp_port_22_1(ec2_client)
    for finding in n_acl_ingress_tcp_22_findings:
        findings.append(finding)

    sg_all_ports_open_findings = ec2_networkacl_allow_ingress_tcp_port_3389_1(ec2_client)
    for finding in sg_all_ports_open_findings:
        findings.append(finding)

    sg_ingress_any_port_findings = ec2_securitygroup_allow_ingress_from_internet_to_any_port_2(ec2_client)
    for finding in sg_ingress_any_port_findings:
        findings.append(finding)

    sg_ingress_mongodb_ports_findings = ec2_securitygroup_allow_ingress_from_internet_to_mongodb_ports(ec2_client)
    for finding in sg_ingress_mongodb_ports_findings:
        findings.append(finding)

    sg_ingress_ftp_ports_findings = ec2_securitygroup_allow_ingress_from_internet_to_ftp_ports(ec2_client)
    for finding in sg_ingress_ftp_ports_findings:
        findings.append(finding)

    sg_ingress_ssh_22_findings = ec2_securitygroup_allow_ingress_from_internet_to_ssh_port_22(ec2_client)
    for finding in sg_ingress_ssh_22_findings:
        findings.append(finding)

    sg_ingress_tcp_3389_findings = ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389_2(ec2_client)
    for finding in sg_ingress_tcp_3389_findings:
        findings.append(finding)
    
    # 결과를 JSON 파일로 저장
    with open('results.json', 'w') as json_file:
        json.dump(findings, json_file, indent=4)

if __name__ == "__main__":
    main()
