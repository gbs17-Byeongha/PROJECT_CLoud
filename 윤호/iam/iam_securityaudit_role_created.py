import json
import boto3

def check_security_audit_role_created(iam):

    # 이 함수는 AWS의 IAM 클라이언트를 사용하여 SecurityAudit 정책이 부착된 역할(Role)을 확인합니다.
    # SecurityAudit(보안감사) 정책이 부착된 역할이 있는 경우 PASS 상태로, 없는 경우 FAIL 상태로 결과를 반환합니다.
    # 함수는 IAM 클라이언트를 생성하고 정책이 부착된 역할을 확인한 후, 그 결과를 findings 리스트에 저장하여 반환합니다.

    # IAM 클라이언트 생성
    # iam = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    # SecurityAudit 정책이 어떤 역할에 부착되어 있는지 확인
    policy_arn = 'arn:aws:iam::aws:policy/SecurityAudit'
    entities_attached = iam.list_entities_for_policy(PolicyArn=policy_arn)
    
    # 정책이 부착된 역할을 필터링하여 리스트에 저장
    role_attached = [entity for entity in entities_attached['PolicyRoles'] if entity['RoleName']]
    
    findings = []
    
    if role_attached:
        # SecurityAudit 정책이 역할에 부착되어 있는 경우 PASS 상태로 결과 저장
        finding = {
            'Region': iam.meta.region_name,  # IAM 클라이언트의 리전 정보
            'ResourceId': 'SecurityAudit',  # 정책의 리소스 ID
            'ResourceArn': policy_arn,  # 정책의 ARN
            'Status': 'PASS',  # 상태 정보
            'StatusExtended': f"{role_attached[0]['RoleName']} 역할에 SecurityAudit 정책이 연결되었습니다."  # 상세 상태 정보
        }
    else:
        # SecurityAudit 정책이 역할에 부착되어 있지 않은 경우 FAIL 상태로 결과 저장
        finding = {
            'Region': iam.meta.region_name,  # IAM 클라이언트의 리전 정보
            'ResourceId': 'SecurityAudit',  # 정책의 리소스 ID
            'ResourceArn': policy_arn,  # 정책의 ARN
            'Status': 'FAIL',  # 상태 정보
            'StatusExtended': "SecurityAudit 정책은 어떤 역할에도 연결되어 있지 않습니다."  # 상세 상태 정보
        }
    
    # 결과를 findings 리스트에 추가
    findings.append(finding)
    
    results = []

    for finding in findings:
        result = {
            'arn': finding['ResourceArn'],
            'tag': '',  # Tag information is not available
            'region': finding['Region'],
            'policy_name': finding['ResourceId'],  # Using ResourceId as policy_name
            'status': finding['Status'],
            'status_extended': finding['StatusExtended']
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
    result = check_security_audit_role_created(iam_client)
    save_findings_to_json(result, "security_audit_role_created.json")
    print("Results saved to 'security_audit_role_created.json'")