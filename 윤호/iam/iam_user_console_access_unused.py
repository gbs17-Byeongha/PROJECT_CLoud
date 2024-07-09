import json
import boto3
import datetime

def check_iam_user_console_access_unused(iam):
    # AWS IAM 사용자의 콘솔 접근 미사용 여부를 점검하는 함수
    # 이 함수는 주어진 AWS 자격 증명을 사용하여 IAM 사용자의 콘솔 접근 권한을 확인하고 
    # 마지막 로그인 시간으로부터 일정 기간(예: 45일) 동안 사용하지 않은 경우 이를 기록합니다.

    # AWS IAM 클라이언트 생성
    # iam = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    
    maximum_expiration_days = 45  # 최대 미사용 일수 설정
    
    findings = []  # 결과를 저장할 리스트
    
    # 모든 IAM 사용자 가져오기
    users = iam.list_users()['Users']
    
    for user in users:  # 각 사용자에 대해 반복
        user_name = user['UserName']  # 사용자 이름
        user_arn = user['Arn']  # 사용자 ARN
        
        # 사용자가 콘솔 접근 권한이 있는지 확인
        try:
            user_info = iam.get_login_profile(UserName=user_name)
            console_access = 'LoginProfile' in user_info
        except iam.exceptions.NoSuchEntityException:
            console_access = False  # 콘솔 접근 권한이 없는 경우 예외 처리
        
        if console_access:
            # 사용자의 마지막 로그인 시간을 가져오기
            if 'PasswordLastUsed' in user_info['LoginProfile']:
                password_last_used = user_info['LoginProfile']['PasswordLastUsed']
                
                # 마지막 로그인 이후 경과 시간 계산
                time_since_last_used = datetime.datetime.now(datetime.timezone.utc) - password_last_used
                
                if time_since_last_used.days > maximum_expiration_days:  # 미사용 기간이 최대 일수를 초과한 경우
                    status = "FAIL"
                    status_extended = f"{user_name} 사용자가 지난 {maximum_expiration_days}일({time_since_last_used.days}일) 동안 콘솔에 로그인하지 않았습니다."  # 실패 메시지
                else:
                    status = "PASS"
                    status_extended = f"{user_name} 사용자가 지난 {maximum_expiration_days}일({time_since_last_used.days}일) 동안 콘솔에 로그인했습니다."  # 성공 메시지
            else:
                status = "PASS"
                status_extended = f"{user_name} 사용자가 콘솔 액세스를 사용하도록 설정했지만 로그인한 적이 없습니다."  # 콘솔 접근 권한이 있으나 로그인 기록이 없음
        else:
            status = "PASS"
            status_extended = f"{user_name} 사용자에게 콘솔 액세스가 사용하도록 설정되어 있지 않거나 사용되지 않습니다."  # 콘솔 접근 권한이 없거나 사용되지 않음을 알림
        
        finding = {
            'resource_id': user_name,
            'resource_arn': user_arn,
            'status': status,
            'status_extended': status_extended  # 상태 세부 설명 추가
        }
        
        findings.append(finding)  # 결과 리스트에 추가
    
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
    result = check_iam_user_console_access_unused(iam_client)
    save_findings_to_json(result, "iam_user_console_access_unused.json")
    print("Results saved to 'iam_user_console_access_unused.json'")