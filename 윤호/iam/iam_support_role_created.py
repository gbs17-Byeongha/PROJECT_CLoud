import json
import boto3

def check_iam_support_role_created(iam_client):
    """
    주어진 AWS 자격 증명을 사용하여 IAM 클라이언트를 생성하고,
    'AWSSupportServiceRolePolicy' 정책(AWS 계정의 서비스 특성 및 사용 데이터에 액세스할 수 있도록 AWS Support에 부여하는 관리형 정책)이 어떤 역할에 연결되어 있는지 확인합니다.
    정책이 역할에 연결되어 있는지 여부에 따라 결과를 반환합니다.
    """
    
    # IAM 클라이언트 생성
    # iam_client = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    role_attached_to_support_policy = None

    try:
        # 지원 역할 정책에 연결된 역할 목록 가져오기
        response = iam_client.list_entities_for_policy(
            PolicyArn='arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy'
        )
        # 정책에 연결된 역할 목록을 가져와 저장
        role_attached_to_support_policy = response.get('PolicyRoles', [])

        findings = []
        if role_attached_to_support_policy:
            # 정책이 역할에 부착되어 있는 경우 PASS 상태로 결과 저장
            report = {
                'region': iam_client.meta.region_name,
                'resource_id': 'AWSSupportServiceRolePolicy',
                'resource_arn': 'arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy',
                'status': 'PASS',
                'status_extended': f"{role_attached_to_support_policy[0]['RoleName']} 역할에 연결된 지원 정책입니다."
            }
        else:
            # 정책이 역할에 부착되어 있지 않은 경우 FAIL 상태로 결과 저장
            report = {
                'region': iam_client.meta.region_name,
                'resource_id': 'AWSSupportServiceRolePolicy',
                'resource_arn': 'arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy',
                'status': 'FAIL',
                'status_extended': '지원 정책은 어떤 역할에도 연결되어 있지 않습니다.'
            }
        # 결과를 findings 리스트에 추가
        findings.append(report)

        results = []

        for finding in findings:
            result = {
            'arn': finding['resource_arn'],
            'tag': '',  # Tag information is not available
            'region': finding['region'],
            'policy_name': '',  # Policy name is not applicable
            'status': finding['status'],
            'status_extended': finding['status_extended']
            }  
            results.append(result)

        return results  # 결과 반환

    except Exception as e:
        # 예외 발생 시 에러 메시지 출력하고 빈 리스트 반환
        print(f"Error: {e}")
        return []

def save_findings_to_json(findings, filename):
    # 결과를 JSON 파일로 저장
    with open(filename, 'w',encoding='UTF-8-sig') as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)

# 결과 실행 및 출력
if __name__ == '__main__':
    iam_client = boto3.client('iam')
    result = check_iam_support_role_created(iam_client)
    save_findings_to_json(result, "iam_support_role_created.json")
    print("Results saved to 'iam_support_role_created.json'")