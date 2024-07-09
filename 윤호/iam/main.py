import json
import boto3
from iam_rotate_access_key_90_days import check_iam_access_key_rotation,generate_credential_report
from iam_securityaudit_role_created import check_security_audit_role_created
from iam_support_role_created import check_iam_support_role_created
from iam_user_accesskey_unused import check_unused_access_keys
from iam_user_console_access_unused import check_iam_user_console_access_unused
from iam_user_hardware_mfa_enabled import check_iam_user_hardware_mfa_enabled
from iam_user_mfa_enabled_console_access import check_iam_user_mfa_enabled_console_access
from iam_user_no_setup_initial_access_key import check_iam_user_no_setup_initial_access_key
from iam_user_two_active_access_key import check_iam_user_two_active_access_keys
from iam_user_with_temporary_credentials import check_iam_user_with_temporary_credentials

def main():
    results = []

    
    iam_client = boto3.client('iam')

    # iam_rotate_access_key_90_days.py
    access_key_findings = check_iam_access_key_rotation(iam_client)
    for finding in access_key_findings:
        results.append(finding)

    # iam_securityaudit_role_created.py
    security_audit_findings = check_security_audit_role_created(iam_client)
    for finding in security_audit_findings:
        results.append(finding)

     # iam_support_role_created.py
    support_role_findings = check_iam_support_role_created(iam_client)
    for finding in support_role_findings:
        results.append(finding)

    # iam_user_accesskey_unused.py
    access_key_unused_findings = check_unused_access_keys(iam_client)
    for finding in access_key_unused_findings:
        results.append(finding)

    # iam_user_console_access_unused.py
    console_access_findings = check_iam_user_console_access_unused(iam_client)
    for finding in console_access_findings:
        results.append(finding)

    # iam_user_hardware_mfa_enabled.py
    mfa_findings = check_iam_user_hardware_mfa_enabled(iam_client)
    for finding in mfa_findings:
        results.append(finding)

    # iam_user_mfa_enabled_console_access.py
    console_mfa_findings = check_iam_user_mfa_enabled_console_access(iam_client)
    for finding in console_mfa_findings:
        results.append(finding)

    # iam_user_no_setup_initial_access_key.py
    no_setup_initial_access_key_findings = check_iam_user_no_setup_initial_access_key(iam_client)
    for finding in no_setup_initial_access_key_findings:
        results.append(finding)

    # iam_user_two_active_access_key.py
    two_active_access_key_findings = check_iam_user_two_active_access_keys(iam_client)
    for finding in two_active_access_key_findings:
        results.append(finding)


    # iam_user_with_temporary_credentials.py
    temporary_credentials_findings = check_iam_user_with_temporary_credentials(iam_client)
    for finding in temporary_credentials_findings:
        results.append(finding)
    
    # Save the results to a JSON file
    with open('results.json', 'w',encoding='UTF-8-sig') as json_file:
        json.dump(results, json_file, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    main()











# import json
# import boto3
# from iam_rotate_access_key_90_days import check_iam_access_key_rotation,generate_credential_report
# from iam_securityaudit_role_created import check_security_audit_role_created
# from iam_support_role_created import check_iam_support_role_created
# from iam_user_accesskey_unused import check_unused_access_keys
# from iam_user_console_access_unused import check_iam_user_console_access_unused
# from iam_user_hardware_mfa_enabled import check_iam_user_hardware_mfa_enabled
# from iam_user_mfa_enabled_console_access import check_iam_user_mfa_enabled_console_access
# from iam_user_no_setup_initial_access_key import check_iam_user_no_setup_initial_access_key
# from iam_user_two_active_access_key import check_iam_user_two_active_access_keys
# from iam_user_with_temporary_credentials import check_iam_user_with_temporary_credentials

# def main():
#     results = []

    
#     iam_client = boto3.client('iam')

#     generate_credential_report(iam_client)


#     # iam_rotate_access_key_90_days.py
#     access_key_findings = check_iam_access_key_rotation(iam_client)
#     for finding in access_key_findings:
#         result = {
#             'Object_name': finding['resource_id'],
#             'arn': finding['resource_arn'],
#             'region': '',  # Region information is not available
#             'tag': '',  # Tag information is not available
#             'policy_name': '',  # Policy name is not applicable
#             'status': finding['status'],
#             'status_extended': finding['status_extended']
#         }
#         results.append(result)

#     # iam_securityaudit_role_created.py
#     security_audit_findings = check_security_audit_role_created(iam_client)
#     for finding in security_audit_findings:
#         result = {
#             'Object_name': finding['ResourceId'],
#             'arn': finding['ResourceArn'],
#             'region': finding['Region'],
#             'tag': '',  # Tag information is not available
#             'policy_name': finding['ResourceId'],  # Using ResourceId as policy_name
#             'status': finding['Status'],
#             'status_extended': finding['StatusExtended']
#         }
#         results.append(result)

#      # iam_support_role_created.py
#     support_role_findings = check_iam_support_role_created(iam_client)
#     for finding in support_role_findings:
#         result = {
#             'Object_name': finding['resource_id'],
#             'arn': finding['resource_arn'],
#             'region': finding['region'],
#             'tag': '',  # Tag information is not available
#             'policy_name': '',  # Policy name is not applicable
#             'status': finding['status'],
#             'status_extended': finding['status_extended']
#         }
#         results.append(result)

#     # iam_user_accesskey_unused.py
#     access_key_unused_findings = check_unused_access_keys(iam_client)
#     for finding in access_key_unused_findings:
#         result = {
#             'Object_name': finding['user'],
#             'arn': finding['arn'],
#             'region': '',  # Region information is not available
#             'tag': '',  # Tag information is not available
#             'policy_name': '',  # Policy name is not applicable
#             'status': finding['status'],
#             'status_extended': finding['message']
#         }
#         results.append(result)

#     # iam_user_console_access_unused.py
#     console_access_findings = check_iam_user_console_access_unused(iam_client)
#     for finding in console_access_findings:
#         result = {
#             'Object_name': finding['resource_id'],
#             'arn': finding['resource_arn'],
#             'region': '',  # Region information is not available
#             'tag': '',  # Tag information is not available
#             'policy_name': '',  # Policy name is not applicable
#             'status': finding['status'],
#             'status_extended': finding['status_extended']
#         }
#         results.append(result)

#     # iam_user_hardware_mfa_enabled.py
#     mfa_findings = check_iam_user_hardware_mfa_enabled(iam_client)
#     for finding in mfa_findings:
#         result = {
#             'Object_name': finding['resource_id'],
#             'arn': finding['resource_arn'],
#             'region': finding['region'],
#             'tag': finding['resource_tags'],  # Tag information is available
#             'policy_name': '',  # Policy name is not applicable
#             'status': finding['status'],
#             'status_extended': finding['status_extended']
#         }
#         results.append(result)

#     # iam_user_mfa_enabled_console_access.py
#     console_mfa_findings = check_iam_user_mfa_enabled_console_access(iam_client)
#     for finding in console_mfa_findings:
#         result = {
#             'Object_name': '',  # Object name is not available
#             'arn': '',  # ARN is not available
#             'region': '',  # Region information is not available
#             'tag': '',  # Tag information is not available
#             'policy_name': '',  # Policy name is not applicable
#             'status': 'WARNING',
#             'status_extended': finding
#         }
#         results.append(result)

#     # iam_user_no_setup_initial_access_key.py
#     no_setup_initial_access_key_findings = check_iam_user_no_setup_initial_access_key(iam_client)
#     for finding in no_setup_initial_access_key_findings:
#         result = {
#             'Object_name': finding['resource_id'],
#             'arn': finding['resource_arn'],
#             'region': '',  # Region information is not available
#             'tag': '',  # Tag information is not available
#             'policy_name': '',  # Policy name is not applicable
#             'status': finding['status'],
#             'status_extended': finding['status_extended']
#         }
#         results.append(result)

#     # iam_user_two_active_access_key.py
#     two_active_access_key_findings = check_iam_user_two_active_access_keys(iam_client)
#     for finding in two_active_access_key_findings:
#         result = {
#             'Object_name': finding['resource_id'],
#             'arn': finding['resource_arn'],
#             'region': '',  # Region information is not available
#             'tag': '',  # Tag information is not available
#             'policy_name': '',  # Policy name is not applicable
#             'status': finding['status'],
#             'status_extended': finding['status_extended']
#         }
#         results.append(result)


#     # iam_user_with_temporary_credentials.py
#     temporary_credentials_findings = check_iam_user_with_temporary_credentials(iam_client)
#     for finding in temporary_credentials_findings:
#         result = {
#             'Object_name': finding['ResourceId'],
#             'arn': finding['ResourceArn'],
#             'region': '',  # Region information is not available
#             'tag': '',  # Tag information is not available
#             'policy_name': '',  # Policy name is not applicable
#             'status': finding['Status'],
#             'status_extended': finding['StatusExtended']
#         }
#         results.append(result)
    
#     # Save the results to a JSON file
#     with open('results.json', 'w') as json_file:
#         json.dump(results, json_file, indent=4)

# if __name__ == "__main__":
#     main()