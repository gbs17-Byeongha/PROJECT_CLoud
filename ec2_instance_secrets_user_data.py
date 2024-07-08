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

# EC2 인스턴스의 User Data를 가져오는 함수
def get_instance_user_data(ec2_client, instance_id):
    try:
        # 인스턴스의 User Data 속성을 가져오는 AWS SDK 호출
        response = ec2_client.describe_instance_attribute(
            InstanceId=instance_id, 
            Attribute='userData'
        )
        # User Data 값 추출
        user_data = response.get('UserData', {}).get('Value', None)
        return user_data
    except ClientError as e:
        # 예외 처리: 인스턴스 User Data를 가져오지 못한 경우
        print(f"Error retrieving user data for instance {instance_id}: {str(e)}")
        return None

# EC2 인스턴스의 User Data에서 비밀 정보가 있는지 확인하는 함수
def ec2_instance_secrets_user_data2(ec2_client):
    findings = []  # 결과를 저장할 리스트 초기화

    ec2_resource = boto3.resource('ec2')  # EC2 리소스 객체 생성

    # 모든 인스턴스 정보를 반복하며 검사
    for instance in ec2_resource.instances.all():
        if instance.state['Name'] != "terminated":  # 종료된 인스턴스는 제외
            report = {
                # "Object_name": instance.id,  # 인스턴스 ID
                "arn": instance.instance_id,  # 인스턴스 ARN
                "tag": instance.tags,  # 인스턴스 태그
                "region": instance.placement['AvailabilityZone'],  # 인스턴스가 위치한 리전
                "status": "PASS",  # 기본 상태는 'PASS'
                "status_extended": f"No secrets found in EC2 instance {instance.id} User Data."  # 기본 상태 설명
            }

            # 인스턴스의 User Data 가져오기
            user_data = get_instance_user_data(ec2_client, instance.id)

            if user_data:
                # 임시 파일 생성하여 User Data 저장
                temp_user_data_file = tempfile.NamedTemporaryFile(delete=False)
                user_data = b64decode(user_data)  # Base64 디코딩

                # GZIP 압축 여부 확인 후 디코딩
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

                # 스캔 결과 가져오기
                detect_secrets_output = secrets.json()
                if detect_secrets_output:
                    # 발견된 비밀 정보가 있을 경우 보고서 업데이트
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} on line {secret['line_number']}"
                            for secret in detect_secrets_output[temp_user_data_file.name]
                        ]
                    )
                    report["status"] = "FAIL"
                    report["status_extended"] = f"Potential secret found in EC2 instance {instance.id} User Data -> {secrets_string}."

                # 임시 파일 삭제
                os.remove(temp_user_data_file.name)
            else:
                # User Data가 비어 있을 경우의 상태 설명
                report["status_extended"] = f"No secrets found in EC2 instance {instance.id} since User Data is empty."

            # 결과 리스트에 보고서 추가
            findings.append(report)

    return findings  # 결과 리스트 반환

if __name__ == "__main__":
    ec2_client = boto3.client('ec2')

    # 함수 호출 및 결과 저장
    result = ec2_instance_secrets_user_data2(ec2_client)

    # 결과를 JSON 형식으로 출력
    print(json.dumps(result, indent=4))

    # 결과를 JSON 형식으로 파일에 저장 (필요 시 주석 해제)
    # with open('ec2_instance_secrets_user_data_results.json', 'w') as json_file:
    #     json.dump(result, json_file, indent=4)
