import json
import boto3

def check_iam_user_hardware_mfa_enabled(iam):
    
    # AWS IAM 사용자가 하드웨어 MFA를 사용하고 있는지 점검하는 함수
    # 이 함수는 주어진 AWS 자격 증명을 사용하여 IAM 사용자의 MFA 설정을 확인하고
    # 하드웨어 MFA가 설정되어 있는지 여부를 검사합니다.
    
    # AWS IAM 클라이언트 생성
    # iam = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    findings = []  # 결과를 저장할 리스트

    # IAM 사용자 목록 가져오기
    users = iam.list_users()['Users']

    for user in users:  # 각 사용자에 대해 반복
        user_name = user['UserName']  # 사용자 이름
        user_arn = user['Arn']  # 사용자 ARN
        user_tags = user.get('Tags', [])  # 사용자 태그 (없을 경우 빈 리스트)

        # 사용자가 MFA 기기를 가지고 있는지 확인
        mfa_devices = iam.list_mfa_devices(UserName=user_name).get('MFADevices', [])
        if mfa_devices:  # MFA 기기가 있을 경우
            has_hardware_mfa = False
            for mfa_device in mfa_devices:
                if mfa_device['SerialNumber'].startswith('arn'):  # 하드웨어 MFA 기기인지 확인
                    has_hardware_mfa = True
                    break

            if has_hardware_mfa:
                finding = {
                    'resource_id': user_name,
                    'resource_arn': user_arn,
                    'resource_tags': user_tags,
                    'region': iam.meta.region_name,
                    'status': 'PASS',
                    'status_extended': f"{user_name} 사용자가 하드웨어 MFA를 사용하도록 설정했습니다."  # 하드웨어 MFA 사용 중
                }
            else:
                finding = {
                    'resource_id': user_name,
                    'resource_arn': user_arn,
                    'resource_tags': user_tags,
                    'region': iam.meta.region_name,
                    'status': 'FAIL',
                    'status_extended': f"{user_name} 사용자가 하드웨어 MFA 디바이스 대신 가상 MFA를 사용하도록 설정했습니다."  # 가상 MFA 사용 중
                }
        else:
            finding = {
                'resource_id': user_name,
                'resource_arn': user_arn,
                'resource_tags': user_tags,
                'region': iam.meta.region_name,
                'status': 'FAIL',
                'status_extended': f"{user_name} 사용자에게 사용하도록 설정된 MFA 유형이 없습니다."  # MFA 미사용
            }

        findings.append(finding)  # 결과 리스트에 추가

    results = []

    for finding in findings:
        result = {
            'arn': finding['resource_arn'],
            'tag': finding['resource_tags'],  # Tag information is available
            'region': finding['region'],
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
    result = check_iam_user_hardware_mfa_enabled(iam_client)
    save_findings_to_json(result, "iam_user_hardware_mfa_enabled.json")
    print("Results saved to 'iam_user_hardware_mfa_enabled.json'")