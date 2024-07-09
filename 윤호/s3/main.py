import json
import boto3
from s3_bucket_default_encryption import check_s3_bucket_default_encryption
from s3_bucket_no_mfa_delete import check_s3_bucket_no_mfa_delete
from s3_bucket_object_lock import check_s3_bucket_object_lock
from s3_bucket_policy_public_write_access import check_s3_bucket_policy_public_write_access
from s3_bucket_public_access import check_s3_bucket_public_access
from s3_bucket_secure_transport_policy import check_s3_bucket_secure_transport_policy


def main():
    results = []

    
    s3_client = boto3.client('s3')


    # s3_bucket_default_encryption.py
    default_encryption_findings = check_s3_bucket_default_encryption(s3_client)
    for finding in default_encryption_findings:
        results.append(finding)

    # s3_bucket_no_mfa_delete.py
    no_mfa_delete_findings = check_s3_bucket_no_mfa_delete(s3_client)
    for finding in no_mfa_delete_findings:
        results.append(finding)

     # s3_bucket_object_lock.py
    object_lock_findings = check_s3_bucket_object_lock(s3_client)
    for finding in object_lock_findings:
        results.append(finding)

    # s3_bucket_policy_public_write_access.py
    policy_public_write_access_findings = check_s3_bucket_policy_public_write_access(s3_client)
    for finding in policy_public_write_access_findings:
        results.append(finding)

    # s3_bucket_public_access.py
    public_access_findings = check_s3_bucket_public_access(s3_client)
    for finding in public_access_findings:
        results.append(finding)

    # s3_bucket_secure_transport_policy.py
    secure_transport_policy_findings = check_s3_bucket_secure_transport_policy(s3_client)
    for finding in secure_transport_policy_findings:
        results.append(finding)

    
    # Save the results to a JSON file
    with open('results.json', 'w',encoding='UTF-8-sig') as json_file:
        json.dump(results, json_file, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    main()
