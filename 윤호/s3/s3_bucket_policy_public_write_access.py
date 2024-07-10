import json
import boto3

def check_s3_bucket_policy_public_write_access(s3):
    """
    Check if S3 buckets have policies which allow public write access.
    """
    findings = []

    # Get list of all buckets
    buckets = s3.list_buckets().get('Buckets', [])

    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            bucket_policy_str = s3.get_bucket_policy(Bucket=bucket_name)['Policy']
            bucket_policy = json.loads(bucket_policy_str)  # 문자열을 딕셔너리로 변환
            statements = bucket_policy.get('Statement', [])
            for statement in statements:
                if (
                    statement.get('Effect') == 'Allow'
                    and 'Principal' in statement
                    and '*' in statement['Principal']
                    and 'Action' in statement
                    and (
                        's3:PutObject' in statement['Action']
                        or 's3:Put*' in statement['Action']
                    )
                ):
                    finding = {
                        'resource_id': bucket_name,
                        'resource_arn': f"arn:aws:s3:::{bucket_name}",
                        'status': 'FAIL',
                        'status_extended': f"S3 버킷 {bucket_name}은(는) 버킷 정책에서 공용 쓰기 액세스를 허용합니다.",
                    }
                    findings.append(finding)
                    break
        except Exception as e:
            finding = {
                'resource_id': bucket_name,
                'resource_arn': f"arn:aws:s3:::{bucket_name}",
                'status': 'ERROR',
                'status_extended': str(e),
            }
            findings.append(finding)

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
    result = check_s3_bucket_policy_public_write_access(s3_client)
    save_findings_to_json(result, "s3_bucket_policy_public_write_access.json")
    print("Results saved to 's3_bucket_policy_public_write_access.json'")
