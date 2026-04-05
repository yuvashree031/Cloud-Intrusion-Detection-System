# Cloud IDS - Cloud Intrusion Detection System

Cloud IDS is a web-based intrusion detection system designed for monitoring AWS cloud environments. It leverages AWS CloudTrail logs and IAM services to detect real-time security threats such as brute force attacks, privilege escalations, unauthorized resource creations, and compliance violations. The application features a user-friendly dashboard with real-time alerts, threat scoring, and manual scanning capabilities, enabling administrators to proactively secure their cloud infrastructure. AWS security monitoring with real-time threat detection and web dashboard.

## Setup

```bash
git clone <repository-url>
cd cloud-ids
pip install -r Requirements.txt
```

Create a `.env` file:

```env
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=ap-south-1
```

Run:

```bash
python app.py
```

Open `http://localhost:5000`

## Demo Mode

Set `DEMO_MODE=true` in `.env` to run without AWS credentials.

## AWS Permissions Required

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudtrail:LookupEvents",
                "s3:ListAllMyBuckets",
                "s3:GetBucketAcl",
                "s3:GetBucketPolicy",
                "ec2:DescribeInstances",
                "ec2:DescribeSecurityGroups",
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:GetUser"
            ],
            "Resource": "*"
        }
    ]
}
```

## Threat Detection Rules

| Rule | Threat                     | Severity |
|------|----------------------------|----------|
| T001 | Brute Force Login          | HIGH     |
| T002 | Root Account Login         | CRITICAL |
| T003 | Security Group Deleted     | HIGH     |
| T004 | CloudTrail Logging Stopped | CRITICAL |
| T005 | New IAM User Created       | MEDIUM   |
| T006 | Privilege Escalation       | HIGH     |
| T007 | EC2 in Unusual Region      | MEDIUM   |
| T008 | Overprivileged Role        | HIGH     |
| T009 | New EC2 Instance Created   | LOW      |
| T010 | New S3 Bucket Created      | LOW      |
| T011 | MFA Not Enabled            | HIGH     |

## API Endpoints

| Method | Endpoint              | Description      |
|--------|-----------------------|------------------|
| GET    | /health               | Health check     |
| GET    | /api/alerts           | List all alerts  |
| PATCH  | /api/alerts/{id}      | Update alert     |
| GET    | /api/threats          | Threat stats     |
| GET    | /api/logs             | CloudTrail logs  |
| POST   | /api/scan             | Manual scan      |
| POST   | /api/monitoring/start | Start monitoring |
| POST   | /api/monitoring/stop  | Stop monitoring  |
| POST   | /api/clear            | Clear alerts     |

## Tech Stack

- Flask, Flask-SocketIO
- boto3 (AWS SDK)
- scikit-learn (anomaly detection)