# s3_bucket_default_encryption.py
import json
import boto3


def check_s3_bucket_default_encryption(s3):
    """
    Check if S3 buckets have default encryption (SSE) enabled or use a bucket policy to enforce it.
    """
    findings = []

    # Get list of all buckets
    buckets = s3.list_buckets().get('Buckets')

    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            # Get bucket encryption configuration
            encryption_config = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption_config.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])

            if rules:
                encryption_enabled = True
                encryption_type = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', 'Unknown')
            else:
                encryption_enabled = False
                encryption_type = 'None'

            if encryption_enabled:
                status = 'PASS'
                status_extended = f"S3 버킷 {bucket_name}에 {encryption_type}(으)로 서버 측 암호화가 있습니다."
            else:
                status = 'FAIL'
                status_extended = f"S3 버킷 {bucket_name}에 서버 측 암호화가 사용되도록 설정되어 있지 않습니다."

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
    result = check_s3_bucket_default_encryption(s3_client)
    save_findings_to_json(result, "s3_bucket_default_encryption.json")
    print("Results saved to 's3_bucket_default_encryption.json'")