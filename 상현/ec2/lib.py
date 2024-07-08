import ipaddress
from typing import Any, Tuple, Dict

# 보안 그룹의 인그레스 규칙을 검사하는 함수
def check_security_group(ingress_rule: Any, protocol: str, ports: list = [], any_address: bool = False) -> bool:
    def _is_cidr_public(cidr: str, any_address: bool = False) -> bool:
        # 공용 CIDR인지 여부를 확인하는 내부 함수
        public_IPv4 = "0.0.0.0/0"
        public_IPv6 = "::/0"
        if cidr in (public_IPv4, public_IPv6):
            return True
        if not any_address:
            return ipaddress.ip_network(cidr).is_global

    if ingress_rule["IpProtocol"] == "-1":
        # 모든 IP 프로토콜을 허용하는 경우
        for ip_ingress_rule in ingress_rule["IpRanges"]:
            if _is_cidr_public(ip_ingress_rule["CidrIp"], any_address):
                return True
        for ip_ingress_rule in ingress_rule["Ipv6Ranges"]:
            if _is_cidr_public(ip_ingress_rule["CidrIpv6"], any_address):
                return True

    if "FromPort" in ingress_rule:
        # 포트 범위가 명시된 경우
        if ingress_rule["FromPort"] != ingress_rule["ToPort"]:
            diff = (ingress_rule["ToPort"] - ingress_rule["FromPort"]) + 1
            ingress_port_range = [int(ingress_rule["FromPort"]) + x for x in range(diff)]
        else:
            ingress_port_range = [int(ingress_rule["FromPort"])]

        for ip_ingress_rule in ingress_rule["IpRanges"]:
            if _is_cidr_public(ip_ingress_rule["CidrIp"], any_address):
                if ports:
                    for port in ports:
                        if port in ingress_port_range and ingress_rule["IpProtocol"] == protocol:
                            return True
                if len(set(ingress_port_range)) == 65536:
                    return True
                if ports is None:
                    return True

        for ip_ingress_rule in ingress_rule["Ipv6Ranges"]:
            if _is_cidr_public(ip_ingress_rule["CidrIpv6"], any_address):
                if ports:
                    for port in ports:
                        if port in ingress_port_range and ingress_rule["IpProtocol"] == protocol:
                            return True
                if len(set(ingress_port_range)) == 65536:
                    return True
                if ports is None:
                    return True

    return False

# 인스턴스의 공개 상태를 확인하는 함수
def get_instance_public_status(vpc_subnets: Dict[str, Any], instance: Any, service: str) -> Tuple[str, str]:
    # 인스턴스의 공개 상태를 확인하고 상태 및 심각도를 반환하는 함수
    status = f"Instance {instance.id} has {service} exposed to 0.0.0.0/0 but with no public IP address."
    severity = "medium"

    if instance.public_ip_address:
        status = f"Instance {instance.id} has {service} exposed to 0.0.0.0/0 on public IP address {instance.public_ip_address} but it is placed in a private subnet {instance.subnet_id}."
        severity = "high"
        if vpc_subnets[instance.subnet_id]['Public']:
            status = f"Instance {instance.id} has {service} exposed to 0.0.0.0/0 on public IP address {instance.public_ip_address} in public subnet {instance.subnet_id}."
            severity = "critical"

    return status, severity

# 네트워크 ACLs를 검사하는 함수
def check_network_acl(rules: Any, protocol: str, port: int) -> bool:
    """NACL의 인바운드 규칙을 검사하여 공용 액세스 여부를 확인하는 함수"""
    
    # IPv6 규칙과 IPv4 규칙을 분리
    rules_IPv6 = list(filter(lambda rule: rule.get("CidrBlock") is None and not rule["Egress"], rules))

    # IPv6에 대한 검사
    # RuleNumber에 따라 규칙 정렬
    for rule in sorted(rules_IPv6, key=lambda rule: rule["RuleNumber"]):
        if (
            rule["Ipv6CidrBlock"] == "::/0"
            and rule["RuleAction"] == "deny"
            and (
                rule["Protocol"] == "-1"
                or (
                    rule["Protocol"] == protocol
                    and rule["PortRange"]["From"] <= port <= rule["PortRange"]["To"]
                )
            )
        ):
            # 해당 포트에 대한 IPv6 거부 규칙이 있는 경우
            break

        if (
            rule["Ipv6CidrBlock"] == "::/0"
            and rule["RuleAction"] == "allow"
            and (
                rule["Protocol"] == "-1"
                or (
                    rule["Protocol"] == protocol
                    and rule["PortRange"]["From"] <= port <= rule["PortRange"]["To"]
                )
            )
        ):
            # 해당 포트에 대한 IPv6 허용 규칙이 있는 경우
            return True

    # IPv6 공용 액세스가 없는 경우

    # IPv4 규칙과 IPv6 규칙을 분리
    rules_IPv4 = list(filter(lambda rule: rule.get("Ipv6CidrBlock") is None and not rule["Egress"], rules))

    # IPv4에 대한 검사
    # RuleNumber에 따라 규칙 정렬
    for rule in sorted(rules_IPv4, key=lambda rule: rule["RuleNumber"]):
        if (
            rule["CidrBlock"] == "0.0.0.0/0"
            and rule["RuleAction"] == "deny"
            and (
                rule["Protocol"] == "-1"
                or (
                    rule["Protocol"] == protocol
                    and rule["PortRange"]["From"] <= port <= rule["PortRange"]["To"]
                )
            )
        ):
            # 해당 포트에 대한 IPv4 거부 규칙이 있고 IPv6에 공용 액세스가 없는 경우
            return False

        if (
            rule["CidrBlock"] == "0.0.0.0/0"
            and rule["RuleAction"] == "allow"
            and (
                rule["Protocol"] == "-1"
                or (
                    rule["Protocol"] == protocol
                    and rule["PortRange"]["From"] <= port <= rule["PortRange"]["To"]
                )
            )
        ):
            # 해당 포트에 대한 IPv4 허용 규칙이 있는 경우
            return True

    return False
