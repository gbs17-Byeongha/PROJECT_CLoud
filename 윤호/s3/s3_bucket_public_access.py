# s3_bucket_public_access.py
import json
import boto3


def check_s3_bucket_public_access(s3):
    """
    Ensure there are no S3 buckets open to Everyone or Any AWS user.
    """
    findings = []

    # Get list of all buckets
    buckets = s3.list_buckets().get('Buckets', [])

    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            # Get bucket public access block configuration
            public_access_block = s3.get_public_access_block(Bucket=bucket_name).get('PublicAccessBlockConfiguration', {})
            bucket_acl = s3.get_bucket_acl(Bucket=bucket_name).get('Grants', [])
            bucket_policy = s3.get_bucket_policy(Bucket=bucket_name).get('Policy', {})

            is_public = False
            status_extended = f"S3 버킷 {bucket_name}이(가) 공개되지 않았습니다."

            # Check if public access block is enabled
            if not (
                public_access_block.get('IgnorePublicAcls', False)
                and public_access_block.get('RestrictPublicBuckets', False)
            ):
                # Check bucket ACL
                for grantee in bucket_acl:
                    if grantee.get('Grantee', {}).get('Type') == 'Group':
                        if grantee['Grantee'].get('URI') in ('http://acs.amazonaws.com/groups/global/AllUsers', 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'):
                            is_public = True
                            status_extended = f"버킷 ACL로 인해 S3 버킷 {bucket_name}에 공용 액세스 권한이 있습니다."
                            break

                # Check bucket policy
                if not is_public:
                    statements = bucket_policy.get('Statement', [])
                    for statement in statements:
                        if (
                            statement.get('Principal') == '*'
                            and statement.get('Effect') == 'Allow'
                        ):
                            is_public = True
                            status_extended = f"버킷 정책으로 인해 S3 버킷 {bucket_name}에 공용 액세스 권한이 있습니다."
                            break
                        elif (
                            statement.get('Principal', {}).get('AWS') == '*'
                            and statement.get('Effect') == 'Allow'
                        ):
                            is_public = True
                            status_extended = f"버킷 정책으로 인해 S3 버킷 {bucket_name}에 공용 액세스 권한이 있습니다."
                            break

            if is_public:
                status = 'FAIL'
            else:
                status = 'PASS'

            findings.append({
                'resource_id': bucket_name,
                'resource_arn': f"arn:aws:s3:::{bucket_name}",
                'status': status,
                'status_extended': status_extended,
            })
        except Exception as e:
            findings.append({
                'resource_id': bucket_name,
                'resource_arn': f"arn:aws:s3:::{bucket_name}",
                'status': 'ERROR',
                'status_extended': str(e),
            })

    results = []

    for finding in findings:
        result = {
            'arn': finding['resource_arn'],
            'tag': '',  # Tag information is not available
            'region': '',  # Region information is not available
            'policy_name': '',  # Policy name is not applicable
            'status': finding['status'],
            'status_extended': finding['status_extended']
        }
        results.append(result)

    return results

def save_findings_to_json(findings, filename):
    # 결과를 JSON 파일로 저장
    with open(filename, 'w',encoding='UTF-8-sig') as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)

# 결과 실행 및 출력
if __name__ == '__main__':
    s3_client = boto3.client('s3')
    result = check_s3_bucket_public_access(s3_client)
    save_findings_to_json(result, "s3_bucket_public_access.json")
    print("Results saved to 's3_bucket_public_access.json'")