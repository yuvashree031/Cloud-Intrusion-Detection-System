#import
import os
import boto3
from dotenv import load_dotenv
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class PermissionAnalyzer:
    
    def __init__(self):
        load_dotenv()
        
        self.aws_key = os.getenv('AWS_ACCESS_KEY_ID')
        self.aws_secret = os.getenv('AWS_SECRET_ACCESS_KEY')
        self.aws_region = os.getenv('AWS_REGION', 'ap-south-1')
        
        self.risky_policies = [
            'AdministratorAccess',
            'PowerUserAccess',
            'IAMFullAccess',
            'SecurityAudit'
        ]
        
        try:
            self.session = boto3.Session(
                aws_access_key_id=self.aws_key,
                aws_secret_access_key=self.aws_secret,
                region_name=self.aws_region
            )
            self.iam = self.session.client('iam')
            logger.info("Permission analyzer initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize permission analyzer: {e}")
            raise
    
    def find_overprivileged_accounts(self):
        risky_identities = []
        scan_time = datetime.now()
        
        try:
            users = self.iam.list_users().get('Users', [])
            for user in users:
                username = user['UserName']
                risk_score, issues = self._analyze_user_permissions(username)
                
                if risk_score > 50:
                    risky_identities.append({
                        'type': 'user',
                        'name': username,
                        'arn': user['Arn'],
                        'risk_score': risk_score,
                        'issues': issues,
                        'created': scan_time
                    })
            
            roles = self.iam.list_roles().get('Roles', [])
            for role in roles:
                rolename = role['RoleName']
                
                if rolename.startswith('AWS') or 'ServiceRole' in rolename:
                    continue
                
                risk_score, issues = self._analyze_role_permissions(rolename)
                
                if risk_score > 50:
                    risky_identities.append({
                        'type': 'role',
                        'name': rolename,
                        'arn': role['Arn'],
                        'risk_score': risk_score,
                        'issues': issues,
                        'created': scan_time
                    })
            
            logger.info(f"Found {len(risky_identities)} overprivileged identities")
            return risky_identities
            
        except Exception as e:
            logger.error(f"Error analyzing permissions: {e}")
            return []
    
    def _analyze_user_permissions(self, username):
        risk_score = 0
        issues = []
        
        try:
            attached_policies = self.iam.list_attached_user_policies(UserName=username)
            for policy in attached_policies.get('AttachedPolicies', []):
                policy_name = policy['PolicyName']
                
                if policy_name == 'SelfEscalationPolicy':
                    risk_score += 60
                    issues.append(f"Has risky policy: {policy_name} - Can escalate own privileges")
                elif policy_name in self.risky_policies:
                    risk_score += 30
                    issues.append(f"Has risky policy: {policy_name}")
                    if policy_name == 'AdministratorAccess':
                        risk_score += 50
                        issues.append("Has full administrator access")
            
            inline_policies = self.iam.list_user_policies(UserName=username)
            if inline_policies.get('PolicyNames'):
                risk_score += 20
                issues.append(f"Has {len(inline_policies['PolicyNames'])} inline policies")
            
            groups = self.iam.list_groups_for_user(UserName=username)
            for group in groups.get('Groups', []):
                group_policies = self.iam.list_attached_group_policies(
                    GroupName=group['GroupName']
                )
                for policy in group_policies.get('AttachedPolicies', []):
                    if policy['PolicyName'] in self.risky_policies:
                        risk_score += 20
                        issues.append(f"Inherits risky policy from group: {policy['PolicyName']}")
            
        except Exception as e:
            logger.error(f"Error analyzing user {username}: {e}")
        
        return min(risk_score, 100), issues
    
    def _analyze_role_permissions(self, rolename):
        risk_score = 0
        issues = []
        
        try:
            attached_policies = self.iam.list_attached_role_policies(RoleName=rolename)
            for policy in attached_policies.get('AttachedPolicies', []):
                policy_name = policy['PolicyName']
                
                if policy_name == 'SelfEscalationPolicy':
                    risk_score += 60
                    issues.append(f"Has risky policy: {policy_name} - Can escalate own privileges")
                elif policy_name in self.risky_policies:
                    risk_score += 30
                    issues.append(f"Has risky policy: {policy_name}")
                    if policy_name == 'AdministratorAccess':
                        risk_score += 50
                        issues.append("Has full administrator access")
            
            inline_policies = self.iam.list_role_policies(RoleName=rolename)
            if inline_policies.get('PolicyNames'):
                risk_score += 20
                issues.append(f"Has {len(inline_policies['PolicyNames'])} inline policies")
            
        except Exception as e:
            logger.error(f"Error analyzing role {rolename}: {e}")
        
        return min(risk_score, 100), issues
    
    def get_all_users(self):
        try:
            response = self.iam.list_users()
            return response.get('Users', [])
        except Exception as e:
            logger.error(f"Error fetching IAM users: {e}")
            return []
    
    def get_all_roles(self):
        try:
            response = self.iam.list_roles()
            roles = [r for r in response.get('Roles', []) 
                    if not r['RoleName'].startswith('AWS')]
            return roles
        except Exception as e:
            logger.error(f"Error fetching IAM roles: {e}")
            return []
    
    def check_user_mfa(self, username):
        try:
            response = self.iam.list_mfa_devices(UserName=username)
            return len(response.get('MFADevices', [])) > 0
        except Exception as e:
            logger.error(f"Error checking MFA for {username}: {e}")
            return False
    
    def get_privilege_escalation_paths(self):
        escalation_risks = []
        
        try:
            users = self.iam.list_users().get('Users', [])
            
            for user in users:
                username = user['UserName']
                
                policies = self.iam.list_attached_user_policies(UserName=username)
                
                for policy in policies.get('AttachedPolicies', []):
                    policy_arn = policy['PolicyArn']
                    
                    try:
                        policy_version = self.iam.get_policy(PolicyArn=policy_arn)
                        version_id = policy_version['Policy']['DefaultVersionId']
                        
                        policy_doc = self.iam.get_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=version_id
                        )
                        
                        escalation_risks.append({
                            'user': username,
                            'policy': policy['PolicyName'],
                            'risk': 'Potential privilege escalation',
                            'severity': 'MEDIUM'
                        })
                    except:
                        pass
            
        except Exception as e:
            logger.error(f"Error detecting privilege escalation: {e}")
        
        return escalation_risks
