import datetime
import json
import boto3

# 자격 증명 보고서를 생성
def generate_credential_report(iam):
    # iam = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    try:
        iam.generate_credential_report()
        print("Credential report generation initiated. This may take a few minutes.")
    except iam.exceptions.CredentialReportNotPresentException:
        print("Credential report does not exist. Creating a new report.")
        iam.generate_credential_report()
        print("Credential report generation initiated. This may take a few minutes.")


# AWS 계정 ID는 별도의 API 호출로 가져와야 함
def get_account_id(iam):
    user_arn = iam.get_user()['User']['Arn']
    account_id = user_arn.split(':')[4]
    return account_id

def check_iam_access_key_rotation(iam):
    # AWS IAM 액세스 키 회전(자격 증명의 주기적 변경) 점검 함수
    # 주어진 AWS 자격 증명을 사용하여 IAM 자격 증명 보고서를 가져오고,
    # 각 사용자의 액세스 키 회전 상태를 점검하여 보고서를 생성합니다.

    generate_credential_report(iam)

    max_days = 90  # 액세스 키 회전 최대 허용 일수
    account_id = get_account_id(iam)
    # iam = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    response = iam.get_credential_report()  # IAM 자격 증명 보고서를 가져옴
    report = response['Content'].decode('UTF-8').splitlines()  # 보고서를 UTF-8로 디코딩하고 줄 단위로 분할

    findings = []  # 결과를 저장할 리스트

    for line in report[1:]:  # 첫 번째 줄은 헤더이므로 무시하고 나머지 줄을 처리
        fields = line.split(',')  # 각 줄을 콤마로 분할
        user = fields[0]  # 사용자 이름
        arn = f"arn:aws:iam::{account_id}:user/{user}"  # 사용자 ARN 생성
        access_key_1_active = fields[8] == "true"  # 첫 번째 액세스 키가 활성화되어 있는지 확인
        access_key_1_last_rotated = fields[9]  # 첫 번째 액세스 키의 자격 증명을 주기적으로 변경한(rotate) 마지막 날짜
        access_key_2_active = fields[16] == "true"  # 두 번째 액세스 키가 활성화되어 있는지 확인
        access_key_2_last_rotated = fields[17]  # 두 번째 액세스 키의 자격 증명을 주기적으로 변경한 날짜

        if access_key_1_active or access_key_2_active:  # 액세스 키가 하나라도 활성화된 경우
            old_access_keys = False  # 오래된 액세스 키 플래그 초기화
            if access_key_1_active:  # 첫 번째 액세스 키가 활성화된 경우
                if access_key_1_last_rotated != "N/A":  # 마지막 회전 날짜가 "N/A"가 아닌 경우
                    last_rotated = datetime.datetime.strptime(access_key_1_last_rotated, "%Y-%m-%dT%H:%M:%S+00:00")
                    days_since_rotation = (datetime.datetime.now() - last_rotated).days  # 마지막 회전 이후 경과 일수 계산
                    if days_since_rotation > max_days:  # 경과 일수가 최대 허용 일수를 초과하는 경우
                        old_access_keys = True
                        findings.append({
                            'resource_id': user,
                            'resource_arn': arn,
                            'status': 'FAIL',
                            'status_extended': f"{user} 사용자가 {max_days}일({days_since_rotation}일) 동안 액세스 키 1을 회전하지 않았습니다."
                        })

            if access_key_2_active:  # 두 번째 액세스 키가 활성화된 경우
                if access_key_2_last_rotated != "N/A":  # 마지막 회전 날짜가 "N/A"가 아닌 경우
                    last_rotated = datetime.datetime.strptime(access_key_2_last_rotated, "%Y-%m-%dT%H:%M:%S+00:00")
                    days_since_rotation = (datetime.datetime.now() - last_rotated).days  # 마지막 회전 이후 경과 일수 계산
                    if days_since_rotation > max_days:  # 경과 일수가 최대 허용 일수를 초과하는 경우
                        old_access_keys = True
                        findings.append({
                            'resource_id': user,
                            'resource_arn': arn,
                            'status': 'FAIL',
                            'status_extended': f"{user} 사용자가 {max_days}일({days_since_rotation}일) 동안 액세스 키 2를 회전하지 않았습니다."
                        })

            if not old_access_keys:  # 오래된 액세스 키가 없는 경우
                findings.append({
                    'resource_id': user,
                    'resource_arn': arn,
                    'status': 'PASS',
                    'status_extended': f"{user} 사용자에게 {max_days}일보다 오래된 액세스 키가 없습니다."
                })
        else:  # 액세스 키가 모두 비활성화된 경우
            findings.append({
                'resource_id': user,
                'resource_arn': arn,
                'status': 'PASS',
                'status_extended': f"{user} 사용자에게 액세스 키가 없습니다."
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

    return results  # 결과 반환


def save_findings_to_json(findings, filename):
    # 결과를 JSON 파일로 저장
    with open(filename, 'w',encoding='UTF-8-sig') as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)

# 결과 실행 및 출력
if __name__ == '__main__':
    iam_client = boto3.client('iam')
    result = check_iam_access_key_rotation(iam_client)
    save_findings_to_json(result, "iam_access_key_rotation.json")
    print("Results saved to 'iam_access_key_rotation.json'")
