import boto3
import argparse
import json
from datetime import datetime
 
def list_users(iam_client):
    users = iam_client.list_users()['Users']
    return [{'Username': user['UserName'], 'CreateDate': user['CreateDate']} for user in users]
 
def list_roles(iam_client):
    roles = iam_client.list_roles()['Roles']
    return [{'RoleName': role['RoleName'], 'CreateDate': role['CreateDate']} for role in roles]
 
def list_user_access_keys(iam_client, username):
    keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
    return [{'AccessKeyId': key['AccessKeyId'], 'Status': key['Status']} for key in keys]
 
def get_user_last_password_usage(iam_client, username):
    response = iam_client.get_user(UserName=username)
    create_date = response['User']['CreateDate']
    last_used = response['User'].get('PasswordLastUsed')
    return {'Username': username, 'CreateDate': create_date, 'LastPasswordUsage': last_used}
 
def list_group_memberships(iam_client, username):
    groups = iam_client.list_groups_for_user(UserName=username)['Groups']
    return [group['GroupName'] for group in groups]
 
def list_mfa_devices(iam_client, username):
    mfa_devices = iam_client.list_mfa_devices(UserName=username)['MFADevices']
    return [{'SerialNumber': device['SerialNumber'], 'EnableDate': device['EnableDate']} for device in mfa_devices]
 
def list_s3_buckets(s3_client):
    buckets = s3_client.list_buckets()['Buckets']
    return [bucket['Name'] for bucket in buckets]
 
def get_bucket_acl(s3_client, bucket_name):
    acl = s3_client.get_bucket_acl(Bucket=bucket_name)
    return acl['Grants']
 
def list_object_versions(s3_client, bucket_name):
    versions = s3_client.list_object_versions(Bucket=bucket_name)['Versions']
    return [{'Key': version['Key'], 'VersionId': version['VersionId']} for version in versions]
 
def list_deleted_objects(s3_client, bucket_name):
    deletions = s3_client.list_object_versions(Bucket=bucket_name, Prefix='', Delimiter='')['DeleteMarkers']
    return [{'Key': deletion['Key'], 'DeletionTime': deletion['LastModified']} for deletion in deletions]
 
def list_bucket_policies(s3_client, bucket_name):
    try:
        policy = s3_client.get_bucket_policy(Bucket=bucket_name)['Policy']
        return json.loads(policy)
    except Exception as e:
        if "NoSuchBucketPolicy" in str(e):
            return None
        else:
            raise e
 
def get_bucket_website_configuration(s3_client, bucket_name):
    try:
        website_config = s3_client.get_bucket_website(Bucket=bucket_name)['WebsiteConfiguration']
        return website_config
    except Exception as e:
        if "NoSuchWebsiteConfiguration" in str(e):
            return None
        else:
            raise e
 
def list_user_permissions(iam_client):
    users = iam_client.list_users()['Users']
    users_with_permissions = []
    for user in users:
        user_info = {'Username': user['UserName'], 'CreateDate': user['CreateDate']}
        user_policies = iam_client.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
        user_permissions = []
        for policy in user_policies:
            policy_name = policy['PolicyName']
            policy_details = iam_client.get_policy(PolicyArn=policy['PolicyArn'])['Policy']
            policy_version = policy_details['DefaultVersionId']
            policy_document = iam_client.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=policy_version)['PolicyVersion']['Document']
            policy_permissions = policy_document.get('Statement', [])
            for statement in policy_permissions:
                if 'Action' in statement:
                    user_permissions.extend(statement['Action'])
        user_info['Permissions'] = user_permissions
        users_with_permissions.append(user_info)
    return users_with_permissions
 
def main():
    parser = argparse.ArgumentParser(description='AWS Resource Enumerator')
    parser.add_argument('--iam', action='store_true', help='Enumerate IAM resources')
    parser.add_argument('--s3', action='store_true', help='Enumerate S3 resources')
    parser.add_argument('--output', type=str, help='Output file path')
    args = parser.parse_args()
 
    iam_client = boto3.client('iam')
    s3_client = boto3.client('s3')
 
    output = {}
 
    if args.iam:
        users = list_users(iam_client)
        roles = list_roles(iam_client)
 
        users_access_keys = {}
        for user in users:
            access_keys = list_user_access_keys(iam_client, user['Username'])
            users_access_keys[user['Username']] = access_keys
 
        users_last_password_usage = []
        for user in users:
            password_usage = get_user_last_password_usage(iam_client, user['Username'])
            users_last_password_usage.append(password_usage)
 
        user_permissions = list_user_permissions(iam_client)
 
        output['IAM'] = {
            'Users': users,
            'Roles': roles,
            'UsersAccessKeys': users_access_keys,
            'UsersLastPasswordUsage': users_last_password_usage,
            'UserPermissions': user_permissions,
            'GroupMemberships': {user['Username']: list_group_memberships(iam_client, user['Username']) for user in users},
            'MfaDevices': {user['Username']: list_mfa_devices(iam_client, user['Username']) for user in users}
        }
 
    if args.s3:
        buckets = list_s3_buckets(s3_client)
        bucket_info = {}
 
        for bucket in buckets:
            acl = get_bucket_acl(s3_client, bucket)
            versions = list_object_versions(s3_client, bucket)
            deleted_objects = list_deleted_objects(s3_client, bucket)
            policies = list_bucket_policies(s3_client, bucket)
            website_config = get_bucket_website_configuration(s3_client, bucket)
            bucket_info[bucket] = {
                'ACL': acl,
                'Versions': versions,
                'DeletedObjects': deleted_objects,
                'BucketPolicies': policies,
                'WebsiteConfiguration': website_config
            }
 
        output['S3'] = {'Buckets': bucket_info}
 
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output, f, default=str, indent=4)
    else:
        print(json.dumps(output, default=str, indent=4))
 
if __name__ == '__main__':
    main()