import os
import tempfile
import zlib
from base64 import b64decode
import boto3
import json
from botocore.exceptions import ClientError
from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

# 인코딩 형식을 반환하는 함수
def get_encoding_format():
    return "utf-8"

# Launch Template의 특정 버전의 User Data를 가져오는 함수
def get_launch_template_user_data(ec2_client, launch_template_id, version):
    try:
        # 해당 Launch Template의 특정 버전 정보를 가져오기
        response = ec2_client.describe_launch_template_versions(
            LaunchTemplateId=launch_template_id,
            Versions=[str(version)]
        )
        version_data = response['LaunchTemplateVersions'][0]
        user_data = version_data['LaunchTemplateData'].get('UserData', None)
        return user_data
    except ClientError as e:
        # 예외 처리: Launch Template의 User Data를 가져오지 못한 경우
        print(f"Error retrieving user data for launch template {launch_template_id}, version {version}: {str(e)}")
        return None

# EC2 Launch Template의 모든 버전에서 비밀 정보가 없는지 확인하는 함수
def ec2_launch_template_no_secrets2(ec2_client):
    findings = []  # 결과를 저장할 리스트 초기화
    try:
        # 모든 Launch Template 정보 가져오기
        response = ec2_client.describe_launch_templates()
        launch_templates = response.get('LaunchTemplates', [])

        if not launch_templates:
            # Launch Template이 없는 경우 예외 처리
            findings.append({
                # "Object_name": "N/A",  # 정책 이름을 가져올 수 없으므로 N/A 설정
                "arn": "N/A",  # ARN을 가져올 수 없으므로 N/A 설정
                "tag": "N/A",  # 태그를 가져올 수 없으므로 N/A 설정
                "region": "N/A",  # 리전을 가져올 수 없으므로 N/A 설정
                "status": "ERROR",  # 상태를 "ERROR"로 설정
                "status_extended": "No launch templates found."  # 설명 메시지를 확장 상태 메시지로 설정
            })
            return findings

        # 각 Launch Template에 대해 검사 수행
        for template in launch_templates:
            report = {
                "region": template['LaunchTemplateId'],  # 리전 정보
                "resource_id": template['LaunchTemplateId'],  # 리소스 ID
                "resource_arn": template['LaunchTemplateId'],  # 리소스 ARN
                "status": "PASS",  # 기본 상태는 'PASS'
                "status_extended": f"No secrets found in User Data of any version for EC2 Launch Template {template['LaunchTemplateName']}."  # 기본 상태 설명
            }

            versions_with_secrets = []  # 비밀 정보가 발견된 버전들을 저장할 리스트

            # Launch Template의 모든 버전 가져오기
            versions_response = ec2_client.describe_launch_template_versions(
                LaunchTemplateId=template['LaunchTemplateId']
            )
            versions = versions_response.get('LaunchTemplateVersions', [])

            for version in versions:
                # 각 버전의 User Data 가져오기
                user_data = get_launch_template_user_data(ec2_client, template['LaunchTemplateId'], version['VersionNumber'])

                if user_data:
                    temp_user_data_file = tempfile.NamedTemporaryFile(delete=False)
                    user_data = b64decode(user_data)

                    # GZIP으로 압축된 경우 해제하여 디코딩
                    if user_data[0:2] == b"\x1f\x8b":  # GZIP 매직 넘버
                        user_data = zlib.decompress(user_data, zlib.MAX_WBITS | 32).decode(get_encoding_format())
                    else:
                        user_data = user_data.decode(get_encoding_format())

                    # 임시 파일에 디코딩된 User Data 쓰기
                    temp_user_data_file.write(bytes(user_data, encoding="raw_unicode_escape"))
                    temp_user_data_file.close()

                    # SecretsCollection 객체 생성 및 파일 스캔
                    secrets = SecretsCollection()
                    with default_settings():
                        secrets.scan_file(temp_user_data_file.name)

                    if secrets.json():
                        # 비밀 정보가 발견된 경우 해당 버전 번호 저장
                        versions_with_secrets.append(str(version['VersionNumber']))

                    # 임시 파일 삭제
                    os.remove(temp_user_data_file.name)

            if versions_with_secrets:
                # 발견된 비밀 정보가 있는 경우 상태와 설명 메시지 업데이트
                report["status"] = "FAIL"
                report["status_extended"] = f"Potential secret found in User Data for EC2 Launch Template {template['LaunchTemplateName']} in template versions: {', '.join(versions_with_secrets)}."

            # 결과 리스트에 보고서 추가
            findings.append(report)

    except ClientError as e:
        # 예외 처리: Launch Template 정보를 가져오지 못한 경우
        findings.append({
            "Object_name": "N/A",  # 정책 이름을 가져올 수 없으므로 N/A 설정
            "arn": "N/A",  # ARN을 가져올 수 없으므로 N/A 설정
            "tag": "N/A",  # 태그를 가져올 수 없으므로 N/A 설정
            "region": "N/A",  # 리전을 가져올 수 없으므로 N/A 설정
            "status": "ERROR",  # 상태를 "ERROR"로 설정
            "status_extended": f"Error retrieving launch templates: {str(e)}"  # 예외 메시지를 확장 상태 메시지로 설정
        })

    return findings  # 결과 리스트 반환

if __name__ == "__main__":
    ec2_client = boto3.client('ec2')

    # 함수 호출 및 결과 저장
    result = ec2_launch_template_no_secrets2(ec2_client)

    # 결과를 JSON 형식으로 출력
    print(json.dumps(result, indent=4))

    # 결과를 JSON 형식으로 파일에 저장 (필요 시 주석 해제)
    # with open('ec2_launch_template_no_secrets_results.json', 'w') as json_file:
    #     json.dump(result, json_file, indent=4)
