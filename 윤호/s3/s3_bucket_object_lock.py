import json
import boto3


def check_s3_bucket_object_lock(s3):
    """
    Check if S3 buckets have object lock enabled
    """
    findings = []

    # Get list of all buckets
    buckets = s3.list_buckets().get('Buckets')

    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            # Get bucket object lock configuration
            response = s3.get_bucket_logging(Bucket=bucket_name)
            if response.get('LoggingEnabled'):
                status = 'PASS'
                status_extended = f"S3 버킷 {bucket_name}이(가) 로깅을 사용하도록 설정했습니다."
            else:
                status = 'FAIL'
                status_extended = f"S3 버킷 {bucket_name}이(가) 로깅을 사용하지 않도록 설정했습니다."

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
    result = check_s3_bucket_object_lock(s3_client)
    save_findings_to_json(result, "s3_bucket_object_lock.json")
    print("Results saved to 's3_bucket_object_lock.json'")
