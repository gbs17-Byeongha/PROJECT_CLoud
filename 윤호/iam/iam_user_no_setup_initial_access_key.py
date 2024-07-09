import json
import boto3

def check_iam_user_no_setup_initial_access_key(iam_client):
    # 이 함수는 IAM 사용자가 설정한 액세스 키를 사용하지 않은 경우를 점검하는 코드입니다.
    findings = []

    # IAM 클라이언트 생성
    # iam_client = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    # 자격 증명 보고서 가져오기
    response = iam_client.get_credential_report()
    credential_report = response['Content'].decode('utf-8').split('\n')

    # 자격 증명 보고서 파싱
    for user in credential_report[1:-1]:  # 첫 번째 행(헤더)와 마지막 빈 행을 제외
        user_details = user.split(',')
        user_name = user_details[0]  # 사용자 이름
        user_arn = user_details[1]  # 사용자 ARN
        password_enabled = user_details[4] == 'true'  # 콘솔 패스워드 활성화 여부
        access_key_1_active = user_details[8] == 'true'  # 액세스 키 1 활성화 여부
        access_key_1_last_used_date = user_details[9]  # 액세스 키 1 마지막 사용 날짜
        access_key_2_active = user_details[14] == 'true'  # 액세스 키 2 활성화 여부
        access_key_2_last_used_date = user_details[15]  # 액세스 키 2 마지막 사용 날짜

        # 콘솔 패스워드가 활성화된 경우
        if password_enabled:
            # 액세스 키 1이 활성화되어 있지만 사용되지 않은 경우
            if (access_key_1_active and access_key_1_last_used_date == 'N/A'):
                finding = {
                    'resource_id': user_name,
                    'resource_arn': user_arn,
                    'status': 'FAIL',
                    'status_extended': f'{user_name} 사용자가 액세스 키 1을(를) 사용한 적이 없습니다.'
                }
                findings.append(finding)

            # 액세스 키 2가 활성화되어 있지만 사용되지 않은 경우
            if (access_key_2_active and access_key_2_last_used_date == 'N/A'):
                finding = {
                    'resource_id': user_name,
                    'resource_arn': user_arn,
                    'status': 'FAIL',
                    'status_extended': f'{user_name} 사용자가 액세스 키 2를 사용한 적이 없습니다.'
                }
                findings.append(finding)
        else:
            # 콘솔 패스워드가 비활성화된 경우
            finding = {
                'resource_id': user_name,
                'resource_arn': user_arn,
                'status': 'PASS',
                'status_extended': f'{user_name} 사용자에게 액세스 키가 없거나 구성된 액세스 키를 사용합니다.'
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

    return results  # 결과 반환

def save_findings_to_json(findings, filename):
    # 결과를 JSON 파일로 저장
    with open(filename, 'w',encoding='UTF-8-sig') as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)

# 결과 실행 및 출력
if __name__ == '__main__':
    iam_client = boto3.client('iam')
    result = check_iam_user_no_setup_initial_access_key(iam_client)
    save_findings_to_json(result, "iam_user_no_setup_initial_access_key.json")
    print("Results saved to 'iam_user_no_setup_initial_access_key.json'")