# s3_bucket_secure_transport_policy.py
import json
import boto3


def check_s3_bucket_secure_transport_policy(s3):
    """
    Check if S3 buckets have secure transport policy.
    """
    findings = []

    # Get list of all buckets
    buckets = s3.list_buckets().get('Buckets', [])

    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            # Get bucket policy
            bucket_policy_str = s3.get_bucket_policy(Bucket=bucket_name).get('Policy', "")
            bucket_policy = json.loads(bucket_policy_str) if bucket_policy_str else {}

            if not bucket_policy:
                status = 'FAIL'
                status_extended = f"S3 버킷 {bucket_name}에 버킷 정책이 없으므로 HTTP 요청을 허용합니다."
            else:
                status = 'FAIL'
                status_extended = f"S3 버킷 {bucket_name}을(를) 사용하면 버킷 정책에서 안전하지 않은 전송을 통해 요청할 수 있습니다."
                statements = bucket_policy.get('Statement', [])
                for statement in statements:
                    if (
                        statement.get('Effect') == 'Deny'
                        and 'Condition' in statement
                        and (
                            's3:PutObject' in statement.get('Action', [])
                            or '*' in statement.get('Action', [])
                            or 's3:*' in statement.get('Action', [])
                        )
                    ):
                        if 'Bool' in statement['Condition']:
                            if 'aws:SecureTransport' in statement['Condition']['Bool']:
                                if statement['Condition']['Bool']['aws:SecureTransport'] == 'false':
                                    status = 'PASS'
                                    status_extended = f"S3 버킷 {bucket_name}에 안전하지 않은 전송을 통한 요청을 거부하는 버킷 정책이 있습니다."

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
    with open(filename, 'w', encoding='UTF-8-sig') as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)

# 결과 실행 및 출력
if __name__ == '__main__':
    s3_client = boto3.client('s3')
    result = check_s3_bucket_secure_transport_policy(s3_client)
    save_findings_to_json(result, "s3_bucket_secure_transport_policy.json")
    print("Results saved to 's3_bucket_secure_transport_policy.json'")
