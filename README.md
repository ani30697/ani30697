# AWS Resource Enumerator

This script allows you to enumerate various AWS IAM (Identity and Access Management) and S3 (Simple Storage Service) resources. It provides insights into users, roles, access keys, passwords, group memberships, MFA (Multi-Factor Authentication) devices, S3 buckets, ACLs (Access Control Lists), object versions, deleted objects, bucket policies, and bucket website configurations.

## Prerequisites

- Python 3.x
- AWS CLI configured with appropriate permissions
- Boto3 library installed (`pip install boto3`)

## Usage

### Command Line Arguments

- `--iam`: Enable IAM resource enumeration.
- `--s3`: Enable S3 resource enumeration.
- `--output <file_path>`: Specify the output file path for the JSON report.

### Example

```bash
python AWS_IAMS3.py --iam --s3 --output output.json
```

This command will enumerate both IAM and S3 resources and save the output to `output.json` file.

## IAM Resources

- Users: Lists all IAM users along with their creation dates.
- Roles: Lists all IAM roles along with their creation dates.
- Users Access Keys: Lists access keys for each IAM user along with their statuses.
- Users Last Password Usage: Lists last password usage for each IAM user.
- User Permissions: Lists permissions for each IAM user.
- Group Memberships: Lists group memberships for each IAM user.
- MFA Devices: Lists MFA devices for each IAM user.

## S3 Resources

- Buckets: Lists all S3 buckets along with detailed information.
  - ACL: Access Control List for each bucket.
  - Versions: Object versions for each bucket.
  - Deleted Objects: Deleted objects for each bucket.
  - Bucket Policies: Policies associated with each bucket.
  - Website Configuration: Website configuration for each bucket.

## Output

The script generates a JSON report containing the enumerated resources.
---
Feel free to adjust the content based on your preferences or additional information you want to include!
