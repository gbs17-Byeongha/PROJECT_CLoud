import json
import boto3
from ec2_instance_port_cassandra_exposed_to_internet import check_ec2_instance_port_cassandra_exposed_to_internet
from ec2_instance_port_cifs_exposed_to_internet import check_ec2_instance_port_cifs_exposed_to_internet
from ec2_instance_port_elasticsearch_kibana_exposed_to_internet import check_ec2_instance_port_elasticsearch_kibana_exposed_to_internet
from ec2_instance_port_ftp_exposed_to_internet import check_ec2_instance_port_ftp_exposed_to_internet
from ec2_instance_port_kafka_exposed_to_internet import check_ec2_instance_port_kafka_exposed_to_internet
from ec2_instance_port_kerberos_exposed_to_internet import check_ec2_instance_port_kerberos_exposed_to_internet
from ec2_instance_port_ldap_exposed_to_internet import check_ec2_instance_port_ldap_exposed_to_internet
from ec2_instance_port_memcached_exposed_to_internet import check_ec2_instance_port_memcached_exposed_to_internet
from ec2_instance_port_mongodb_exposed_to_internet import check_ec2_instance_port_mongodb_exposed_to_internet
from ec2_instance_port_mysql_exposed_to_internet import check_ec2_instance_port_mysql_exposed_to_internet
from ec2_instance_port_oracle_exposed_to_internet import check_ec2_instance_port_oracle_exposed_to_internet
from ec2_instance_port_postgresql_exposed_to_internet import check_ec2_instance_port_postgresql_exposed_to_internet
from ec2_instance_port_rdp_exposed_to_internet import check_ec2_instance_port_rdp_exposed_to_internet
from ec2_instance_port_redis_exposed_to_internet import check_ec2_instance_port_redis_exposed_to_internet
from ec2_instance_port_sqlserver_exposed_to_internet import check_ec2_instance_port_sqlserver_exposed_to_internet


def main():
    results = []

    
    ec2_client = boto3.client('ec2')



    # ec2_instance_port_cassandra_exposed_to_internet.py
    cassandra_exposed_findings = check_ec2_instance_port_cassandra_exposed_to_internet(ec2_client)
    for finding in cassandra_exposed_findings:
        results.append(finding)

    # ec2_instance_port_cifs_exposed_to_internet.py
    cifs_exposed_findings = check_ec2_instance_port_cifs_exposed_to_internet(ec2_client)
    for finding in cifs_exposed_findings:
        results.append(finding)

     # ec2_instance_port_elasticsearch_kibana_exposed_to_internet.py
    elasticsearch_kibana_exposed_findings = check_ec2_instance_port_elasticsearch_kibana_exposed_to_internet(ec2_client)
    for finding in elasticsearch_kibana_exposed_findings:
        results.append(finding)

    # ec2_instance_port_ftp_exposed_to_internet.py
    ftp_exposed_findings = check_ec2_instance_port_ftp_exposed_to_internet(ec2_client)
    for finding in ftp_exposed_findings:
        results.append(finding)

    # ec2_instance_port_kafka_exposed_to_internet.py
    kafka_exposed_findings = check_ec2_instance_port_kafka_exposed_to_internet(ec2_client)
    for finding in kafka_exposed_findings:
        results.append(finding)

    # ec2_instance_port_kerberos_exposed_to_internet.py
    kerberos_exposed_findings = check_ec2_instance_port_kerberos_exposed_to_internet(ec2_client)
    for finding in kerberos_exposed_findings:
        results.append(finding)

    # ec2_instance_port_ldap_exposed_to_internet.py
    ldap_exposed_findings = check_ec2_instance_port_ldap_exposed_to_internet(ec2_client)
    for finding in ldap_exposed_findings:
        results.append(finding)

    # ec2_instance_port_memcached_exposed_to_internet.py
    memcached_exposed_findings = check_ec2_instance_port_memcached_exposed_to_internet(ec2_client)
    for finding in memcached_exposed_findings:
        results.append(finding)

    # ec2_instance_port_mongodb_exposed_to_internet.py
    mongodb_exposed_findings = check_ec2_instance_port_mongodb_exposed_to_internet(ec2_client)
    for finding in mongodb_exposed_findings:
        results.append(finding)


    # ec2_instance_port_mysql_exposed_to_internet.py
    mysql_exposed_findings = check_ec2_instance_port_mysql_exposed_to_internet(ec2_client)
    for finding in mysql_exposed_findings:
        results.append(finding)

    # ec2_instance_port_oracle_exposed_to_internet.py
    oracle_exposed_findings = check_ec2_instance_port_oracle_exposed_to_internet(ec2_client)
    for finding in oracle_exposed_findings:
        results.append(finding)

    # ec2_instance_port_postgresql_exposed_to_internet.py
    postgresql_exposed_findings = check_ec2_instance_port_postgresql_exposed_to_internet(ec2_client)
    for finding in postgresql_exposed_findings:
        results.append(finding)

    # ec2_instance_port_rdp_exposed_to_internet.py
    rdp_exposed_findings = check_ec2_instance_port_rdp_exposed_to_internet(ec2_client)
    for finding in rdp_exposed_findings:
        results.append(finding)

    # ec2_instance_port_redis_exposed_to_internet.py
    redis_exposed_findings = check_ec2_instance_port_redis_exposed_to_internet(ec2_client)
    for finding in redis_exposed_findings:
        results.append(finding)

    # ec2_instance_port_sqlserver_exposed_to_internet.py
    sqlserver_exposed_findings = check_ec2_instance_port_sqlserver_exposed_to_internet(ec2_client)
    for finding in sqlserver_exposed_findings:
        results.append(finding)
    
    # Save the results to a JSON file
    with open('results.json', 'w',encoding='UTF-8-sig') as json_file:
        json.dump(results, json_file, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    main()
