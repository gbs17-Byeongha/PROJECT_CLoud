import json
import boto3
from datetime import datetime, timedelta, timezone

def check_iam_user_with_temporary_credentials(iam):
   """
   IAM 사용자가 장기 자격 증명(액세스 키)을 사용하여 IAM 또는 STS 외의 다른 AWS 서비스에 접근하는지 확인함으로써,
   보안 위험을 줄이고 잘못된 구성이나 과도한 권한 부여를 방지하는 데 도움을 줍니다.
   """
   findings = []
   
   # IAM 클라이언트 생성
#    iam = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
   
   # 모든 사용자 가져오기
   users = iam.list_users()['Users']
   
   # 각 사용자에 대해 반복
   for user in users:
       user_name = user['UserName']
       user_arn = user['Arn']
       
       # 사용자가 액세스 키를 가지고 있는지 확인하고, 마지막 사용 시점을 확인
       access_keys = iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
       
       # 사용자가 액세스 키를 가지고 있을 경우
       if access_keys:
           last_used_services = set()
           for access_key in access_keys:
               access_key_id = access_key['AccessKeyId']
               last_used = iam.get_access_key_last_used(AccessKeyId=access_key_id)
               
               # 액세스 키가 지난 90일 내에 사용되었는지 확인
               if 'LastUsedDate' in last_used['AccessKeyLastUsed']:
                   last_used_date = last_used['AccessKeyLastUsed']['LastUsedDate']
                   if last_used_date > datetime.now(timezone.utc) - timedelta(days=90):
                       last_used_services.update(last_used['AccessKeyLastUsed']['ServiceName'])
                       
           # 사용된 서비스 목록에서 IAM 및 STS 제거
           last_used_services.discard('iam')
           last_used_services.discard('sts')
           
           # 사용자가 IAM 또는 STS 외의 서비스에 대해 장기 자격 증명을 사용한 경우, 발견 사항 추가
           if last_used_services:
               finding = {
                   'ResourceId': user_name,
                   'ResourceArn': user_arn,
                   'Status': 'FAIL',
                   'StatusExtended': f'{user_name} 사용자는 IAM 또는 STS가 아닌 다른 서비스에 액세스할 수 있는 자격 증명을 오래 사용했습니다.',
                   'Services': list(last_used_services)
               }
               findings.append(finding)
           else:
               # 사용자가 IAM 또는 STS 외의 서비스에 대해 장기 자격 증명을 사용하지 않은 경우
               finding = {
                   'ResourceId': user_name,
                   'ResourceArn': user_arn,
                   'Status': 'PASS',
                   'StatusExtended': f"{user_name} 사용자에게 IAM 또는 STS 이외의 다른 서비스에 액세스할 수 있는 오래된 자격 증명이 없습니다."
               }
               findings.append(finding)
       else:
           # 사용자가 액세스 키를 가지고 있지 않은 경우
           finding = {
               'ResourceId': user_name,
               'ResourceArn': user_arn,
               'Status': 'PASS',
               'StatusExtended': f"{user_name} 사용자에게 IAM 또는 STS 이외의 다른 서비스에 액세스할 수 있는 오래된 자격 증명이 없습니다."
           }
           findings.append(finding)
           
   results = []

   for finding in findings:
        result = {
            'arn': finding['ResourceArn'],
            'tag': '',  # Tag information is not available
            'region': '',  # Region information is not available
            'policy_name': '',  # Policy name is not applicable
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
    result = check_iam_user_with_temporary_credentials(iam_client)
    save_findings_to_json(result, "iam_user_with_temporary_credentials.json")
    print("Results saved to 'iam_user_with_temporary_credentials.json'")