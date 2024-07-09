import json
import boto3

def check_iam_user_mfa_enabled_console_access(iam_client):
    # 이 함수는 IAM 사용자가 콘솔 패스워드를 활성화했지만 MFA를 비활성화한 경우를 점검하는 코드입니다.

    # IAM 클라이언트 생성
    # iam_client = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    # 자격 증명 보고서 가져오기
    credential_report = iam_client.get_credential_report()['Content'].decode('utf-8').split('\n')

    # 결과를 저장할 리스트
    findings = []

    # 각 IAM 사용자에 대해 점검 수행
    for user in credential_report[1:-1]:  # 첫 번째 행(헤더)과 마지막 빈 행을 제외
        user_details = user.split(',')
        user_name = user_details[0]  # 사용자 이름
        password_enabled = user_details[12] == 'true'  # 콘솔 패스워드 활성화 여부
        mfa_enabled = user_details[13] == 'true'  # MFA 활성화 여부

        # 루트 계정은 제외
        if user_name != '<root_account>':
            # 콘솔 패스워드가 활성화되어 있고 MFA가 비활성화된 경우 경고 추가
            if password_enabled and not mfa_enabled:
                result = f"경고: {user_name} 사용자가 콘솔 암호를 사용하도록 설정했지만 MFA를 사용하지 않도록 설정했습니다."  # 경고 메시지
                findings.append(result)

    results = []

    for finding in findings:
        result = {
            'arn': '',  # ARN is not available
            'tag': '',  # Tag information is not available
            'region': '',  # Region information is not available
            'policy_name': '',  # Policy name is not applicable
            'status': 'WARNING',
            'status_extended': finding
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
    result = check_iam_user_mfa_enabled_console_access(iam_client)
    save_findings_to_json(result, "iam_user_mfa_enabled_console_access.json")
    print("Results saved to 'iam_user_mfa_enabled_console_access.json'")