import json
import boto3
import datetime

def check_unused_access_keys(iam_client):
    """
    주어진 AWS 자격 증명을 사용하여 IAM 클라이언트를 생성하고,
    IAM 사용자들의 접근 키 사용 여부를 확인합니다.
    마지막으로 사용된 날짜가 45일을 초과한 접근 키가 있는지 검사하고 결과를 반환합니다.
    """

    max_unused_days = 45  # 최대 사용하지 않은 일 수를 설정
    # iam_client = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    response = iam_client.get_credential_report()  # 자격 증명 보고서 가져오기
    credential_report_content  = response.get('Content').decode('UTF-8').splitlines()  # 보고서 내용을 줄 단위로 분할

    findings = []  # 결과를 저장할 리스트
    header = credential_report_content[0].split(',')
    user_index = header.index('user')
    arn_index = header.index('arn')
    access_key_1_active_index = header.index('access_key_1_active')
    access_key_1_last_used_date_index = header.index('access_key_1_last_used_date')
    access_key_2_active_index = header.index('access_key_2_active')
    access_key_2_last_used_date_index = header.index('access_key_2_last_used_date')

    for user in credential_report_content[1:]:  # 각 사용자에 대해 반복
        user_data = user.split(',')
        user_name = user_data[user_index]
        user_arn = user_data[arn_index]
        access_key_1_active = user_data[access_key_1_active_index]
        access_key_1_last_used_date = user_data[access_key_1_last_used_date_index]
        access_key_2_active = user_data[access_key_2_active_index]
        access_key_2_last_used_date = user_data[access_key_2_last_used_date_index]

        # 사용자가 활성화된 접근 키가 없는 경우
        if access_key_1_active != 'true' and access_key_2_active != 'true':
            findings.append({
                'user': user_name,
                'arn': user_arn,
                'status': 'PASS',
                'message': f'{user_name} 사용자에게 액세스 키가 없습니다.'  # 접근 키가 없음을 알림
            })
        else:
            old_access_keys = False  # 오래된 접근 키 여부를 추적

            # 접근 키 1이 활성화된 경우
            if access_key_1_active == 'true':
                last_used_date = access_key_1_last_used_date
                if last_used_date != 'N/A':
                    last_used_days = (datetime.datetime.now() - datetime.datetime.strptime(last_used_date, '%Y-%m-%dT%H:%M:%S+00:00')).days
                    if last_used_days > max_unused_days:  # 마지막 사용 날짜가 최대 미사용 일수를 초과한 경우
                        old_access_keys = True
                        findings.append({
                            'user': user_name,
                            'arn': user_arn,
                            'status': 'FAIL',
                            'message': f'{user_name} 사용자가 지난 {max_unused_days}일({last_used_days}일) 동안 액세스 키 1을 사용하지 않았습니다.'  # 오래된 접근 키 정보 추가
                        })

            # 접근 키 2가 활성화된 경우
            if access_key_2_active == 'true':
                last_used_date = access_key_2_last_used_date
                if last_used_date != 'N/A':
                    last_used_days = (datetime.datetime.now() - datetime.datetime.strptime(last_used_date, '%Y-%m-%dT%H:%M:%S+00:00')).days
                    if last_used_days > max_unused_days:  # 마지막 사용 날짜가 최대 미사용 일수를 초과한 경우
                        old_access_keys = True
                        findings.append({
                            'user': user_name,
                            'arn': user_arn,
                            'status': 'FAIL',
                            'message': f'{user_name} 사용자가 지난 {max_unused_days}일({last_used_days}일) 동안 액세스 키 2를 사용하지 않았습니다.'  # 오래된 접근 키 정보 추가
                        })

            # 오래된 접근 키가 없는 경우
            if not old_access_keys:
                findings.append({
                    'user': user_name,
                    'arn': user_arn,
                    'status': 'PASS',
                    'message': f'{user_name} 사용자에게 {max_unused_days}일 동안 사용되지 않은 액세스 키가 없습니다.'  # 모든 접근 키가 최근에 사용되었음을 알림
                })

    results = []

    for finding in findings:
        result = {
            'arn': finding['arn'],
            'tag': '',  # Tag information is not available
            'region': '',  # Region information is not available
            'policy_name': '',  # Policy name is not applicable
            'status': finding['status'],
            'status_extended': finding['message']
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
    result = check_unused_access_keys(iam_client)
    save_findings_to_json(result, "unused_access_keys.json")
    print("Results saved to 'unused_access_keys.json'")