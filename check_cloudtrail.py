import os
import boto3
from datetime import datetime, timedelta
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)

class CloudTrailMonitor:
    
    def __init__(self):
        load_dotenv()
        
        self.aws_key = os.getenv('AWS_ACCESS_KEY_ID')
        self.aws_secret = os.getenv('AWS_SECRET_ACCESS_KEY')
        self.aws_region = os.getenv('AWS_REGION', 'ap-south-1')
        
        try:
            self.session = boto3.Session(
                aws_access_key_id=self.aws_key,
                aws_secret_access_key=self.aws_secret,
                region_name=self.aws_region
            )
            self.cloudtrail = self.session.client('cloudtrail')
            self.ec2 = self.session.client('ec2')
            self.iam = self.session.client('iam')
            self.s3 = self.session.client('s3')
            logger.info("CloudTrail monitor initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize CloudTrail monitor: {e}")
            raise
    
    def get_recent_events(self, max_results=100, lookback_minutes=60):
        try:
            response = self.cloudtrail.lookup_events(
                MaxResults=max_results
            )
            
            events = []
            for event in response.get('Events', []):
                processed_event = self._process_event(event)
                if processed_event:
                    events.append(processed_event)
            
            login_events = self.get_console_login_events()
            events.extend(login_events)
            
            logger.info(f"Fetched {len(events)} CloudTrail events")
            
            return events
            
        except Exception as e:
            logger.error(f"Error fetching CloudTrail events: {e}")
            return []
    
    def get_console_login_events(self, max_results=50):
        try:
            us_east_session = boto3.Session(
                aws_access_key_id=self.aws_key,
                aws_secret_access_key=self.aws_secret,
                region_name='us-east-1'
            )
            us_east_cloudtrail = us_east_session.client('cloudtrail')
            
            response = us_east_cloudtrail.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': 'ConsoleLogin'
                    }
                ],
                MaxResults=max_results
            )
            
            events = []
            for event in response.get('Events', []):
                processed_event = self._process_event(event)
                if processed_event:
                    events.append(processed_event)
            
            return events
            
        except Exception as e:
            logger.error(f"Error fetching ConsoleLogin events: {e}")
            return []
    
    def _process_event(self, raw_event):
        try:
            import json
            ct_event_str = raw_event.get('CloudTrailEvent', '{}')
            ct_event = json.loads(ct_event_str) if isinstance(ct_event_str, str) else ct_event_str
            
            source_ip = ct_event.get('sourceIPAddress', raw_event.get('SourceIPAddress', 'unknown'))
            
            return {
                'EventName': raw_event.get('EventName', 'Unknown'),
                'EventTime': raw_event.get('EventTime', datetime.now()),
                'Username': raw_event.get('Username', 'unknown'),
                'SourceIPAddress': source_ip,
                'EventSource': raw_event.get('EventSource', 'unknown'),
                'ErrorCode': raw_event.get('ErrorCode'),
                'ErrorMessage': raw_event.get('ErrorMessage'),
                'Resources': raw_event.get('Resources', []),
                'CloudTrailEvent': ct_event_str
            }
        except Exception as e:
            logger.error(f"Error processing event: {e}")
            return None
    
    def get_ec2_instances(self):
        try:
            response = self.ec2.describe_instances()
            instances = []
            
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_name = 'Unnamed'
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            instance_name = tag['Value']
                            break
                    
                    instances.append({
                        'InstanceId': instance.get('InstanceId'),
                        'InstanceName': instance_name,
                        'InstanceType': instance.get('InstanceType'),
                        'State': instance.get('State', {}).get('Name'),
                        'LaunchTime': instance.get('LaunchTime'),
                        'Region': self.aws_region
                    })
            
            return instances
        except Exception as e:
            logger.error(f"Error fetching EC2 instances: {e}")
            return []
    
    def get_s3_buckets(self):
        try:
            response = self.s3.list_buckets()
            buckets = []
            
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                bucket_info = {
                    'Name': bucket_name,
                    'CreationDate': bucket.get('CreationDate'),
                    'Encrypted': self._check_bucket_encryption(bucket_name),
                    'Versioning': self._check_bucket_versioning(bucket_name),
                    'PublicAccess': self._check_bucket_public_access(bucket_name)
                }
                buckets.append(bucket_info)
            
            return buckets
        except Exception as e:
            logger.error(f"Error fetching S3 buckets: {e}")
            return []
    
    def _check_bucket_encryption(self, bucket_name):
        try:
            self.s3.get_bucket_encryption(Bucket=bucket_name)
            return True
        except:
            return False
    
    def _check_bucket_versioning(self, bucket_name):
        try:
            response = self.s3.get_bucket_versioning(Bucket=bucket_name)
            return response.get('Status') == 'Enabled'
        except:
            return False
    
    def _check_bucket_public_access(self, bucket_name):
        try:
            response = self.s3.get_public_access_block(Bucket=bucket_name)
            config = response.get('PublicAccessBlockConfiguration', {})
            return not all([
                config.get('BlockPublicAcls', False),
                config.get('IgnorePublicAcls', False),
                config.get('BlockPublicPolicy', False),
                config.get('RestrictPublicBuckets', False)
            ])
        except:
            return True