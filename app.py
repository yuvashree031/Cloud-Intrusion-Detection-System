
import os
import json
import uuid
from datetime import datetime
from threading import Thread
import time
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv
import logging

from check_cloudtrail import CloudTrailMonitor
from check_permissions import PermissionAnalyzer


load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'cloud-ids-secret-key-2026')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

alerts_db = []
monitoring_active = False
monitoring_thread = None

class ThreatDetectionEngine:
    
    def __init__(self):
        self.cloudtrail_monitor = CloudTrailMonitor()
        self.permission_analyzer = PermissionAnalyzer()
        self.threat_rules = self._load_threat_rules()
    
    def _load_threat_rules(self):
        return {
            'T001': {'name': 'Brute Force Login', 'severity': 'HIGH'},
            'T002': {'name': 'Root Account Login', 'severity': 'CRITICAL'},
            'T003': {'name': 'Security Group Deleted', 'severity': 'HIGH'},
            'T004': {'name': 'CloudTrail Logging Stopped', 'severity': 'CRITICAL'},
            'T005': {'name': 'New IAM User Created', 'severity': 'MEDIUM'},
            'T006': {'name': 'Privilege Escalation', 'severity': 'HIGH'},
            'T007': {'name': 'EC2 in Unusual Region', 'severity': 'MEDIUM'},
            'T008': {'name': 'Overprivileged Role', 'severity': 'HIGH'},
            'T009': {'name': 'New EC2 Instance Created ', 'severity': 'Low'},
            'T010': {'name': 'New S3 Bucket Created ', 'severity': 'Low'},
            'T011': {'name': 'MFA Not Enabled', 'severity': 'HIGH'}
        }
    
    def analyze_cloudtrail_events(self, events):
        threats = []
        for event in events:
            event_name = event.get('EventName', '')
            username = event.get('Username', 'unknown')
            source_ip = event.get('SourceIPAddress', 'unknown')
            event_time = event.get('EventTime', datetime.now())
            error_code = event.get('ErrorCode', '')
            
            if event_name == 'ConsoleLogin' and ('Root' in username or 'root' in username.lower()):
                threats.append(self._create_alert(
                    'T002',
                    f'Root account console login from {source_ip}',
                    event,
                    username,
                    source_ip
                ))
            
            elif event_name == 'DeleteSecurityGroup':
                threats.append(self._create_alert(
                    'T003',
                    f'Security group deleted by {username}',
                    event,
                    username,
                    source_ip
                ))
            
            elif event_name == 'StopLogging':
                threats.append(self._create_alert(
                    'T004',
                    f'CloudTrail logging stopped by {username}',
                    event,
                    username,
                    source_ip
                ))
            
            elif event_name == 'CreateUser':
                threats.append(self._create_alert(
                    'T005',
                    f'New IAM user created by {username}',
                    event,
                    username,
                    source_ip
                ))
            
            elif event_name in ['AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy']:
                threats.append(self._create_alert(
                    'T006',
                    f'Privilege escalation: {event_name} by {username}',
                    event,
                    username,
                    source_ip
                ))
            
            elif error_code and 'Failed authentication' in str(error_code):
                threats.append(self._create_alert(
                    'T001',
                    f'Failed login attempt for {username} from {source_ip}',
                    event,
                    username,
                    source_ip
                ))
            
            else:
                threats.append({
                    'alert_id': str(uuid.uuid4()),
                    'rule_id': 'INFO',
                    'severity': 'LOW',
                    'title': f'AWS Activity: {event_name}',
                    'description': f'{username} performed {event_name}',
                    'source_ip': source_ip,
                    'user': username,
                    'timestamp': event_time.isoformat() if hasattr(event_time, 'isoformat') else str(event_time),
                    'raw_event': event,
                    'auto_remediated': False,
                    'status': 'OPEN'
                })
        
        threats.extend(self._detect_brute_force(events))
        return threats

    #detect brute force
    def _detect_brute_force(self, events):
        threats = []
        failed_logins = {}
        
        for event in events:
            if event.get('ErrorCode') and 'Login' in event.get('EventName', ''):
                source_ip = event.get('SourceIPAddress', 'unknown')
                event_time = event.get('EventTime', datetime.now())
                
                if source_ip not in failed_logins:
                    failed_logins[source_ip] = []
                
                failed_logins[source_ip].append(event_time)
        
        for source_ip, timestamps in failed_logins.items():
            if len(timestamps) >= 5:
                time_diff = (max(timestamps) - min(timestamps)).total_seconds()
                if time_diff <= 60:
                    threats.append(self._create_alert(
                        'T001',
                        f'Brute force attack detected: {len(timestamps)} failed logins from {source_ip} in {int(time_diff)}s',
                        {'source_ip': source_ip, 'attempts': len(timestamps)},
                        'multiple',
                        source_ip
                    ))
        
        return threats
    
    def analyze_iam_permissions(self):
        threats = []
        
        try:
            risky_identities = self.permission_analyzer.find_overprivileged_accounts()
            
            for identity in risky_identities:
                threats.append(self._create_alert(
                    'T008',
                    f'Overprivileged account detected: {identity["name"]}',
                    identity,
                    identity['name'],
                    'N/A'
                ))
        except Exception as e:
            logger.error(f"IAM analysis error: {e}")
        
        return threats
    
    def _create_alert(self, rule_id, description, raw_event, user, source_ip):
        rule = self.threat_rules.get(rule_id, {})
        
        # Use event timestamp if available, otherwise use current time
        event_timestamp = raw_event.get('timestamp') or raw_event.get('EventTime') or raw_event.get('created')
        if event_timestamp and hasattr(event_timestamp, 'isoformat'):
            timestamp_str = event_timestamp.isoformat()
        else:
            timestamp_str = datetime.now().isoformat()
        
        return {
            'alert_id': str(uuid.uuid4()),
            'rule_id': rule_id,
            'severity': rule.get('severity', 'MEDIUM'),
            'title': rule.get('name', 'Unknown Threat'),
            'description': description,
            'source_ip': source_ip,
            'user': user,
            'timestamp': timestamp_str,
            'raw_event': raw_event,
            'auto_remediated': False,
            'status': 'OPEN'
        }
    
    def calculate_threat_score(self, alerts):
        total_score = 0
        
        login_events = [a for a in alerts if a.get('rule_id') == 'CONSOLE-LOGIN']
        
        login_events.sort(key=lambda x: x.get('timestamp', ''))
        
        failed_attempts_by_ip = {}
        
        for alert in login_events:
            source_ip = alert.get('source_ip', 'unknown')
            is_failed = 'Failed' in alert.get('title', '')
            
            if source_ip not in failed_attempts_by_ip:
                failed_attempts_by_ip[source_ip] = 0
            
            if is_failed:
                total_score += 50
                failed_attempts_by_ip[source_ip] += 1
            else:
                if failed_attempts_by_ip[source_ip] >= 2:
                    total_score += 100
                    failed_attempts_by_ip[source_ip] = 0
                else:
                    failed_attempts_by_ip[source_ip] = 0
        
        return min(total_score, 1000)

detection_engine = ThreatDetectionEngine()

def background_monitor():
    global monitoring_active, alerts_db
    
    logger.info("Background monitoring started")
    
    while monitoring_active:
        try:
            events = detection_engine.cloudtrail_monitor.get_recent_events(max_results=100)
            
            new_threats = detection_engine.analyze_cloudtrail_events(events)
            
            iam_threats = detection_engine.analyze_iam_permissions()
            new_threats.extend(iam_threats)
            
            for threat in new_threats:
                if threat not in alerts_db:
                    alerts_db.append(threat)
                    logger.info(f"New threat detected: {threat['rule_id']} - {threat['title']}")
                    
                    socketio.emit('new_alert', threat)
            
            if len(alerts_db) > 1000:
                alerts_db = alerts_db[-1000:]
            
            time.sleep(30)
            
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
            time.sleep(30)

@app.route('/')
def dashboard():
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'monitoring_active': monitoring_active,
        'total_alerts': len(alerts_db)
    })

@app.route('/api/alerts')
def get_alerts():
    severity = request.args.get('severity')
    status = request.args.get('status')
    limit = int(request.args.get('limit', 100))
    
    filtered_alerts = alerts_db
    
    if severity:
        filtered_alerts = [a for a in filtered_alerts if a['severity'] == severity.upper()]
    
    if status:
        filtered_alerts = [a for a in filtered_alerts if a['status'] == status.upper()]
    
    filtered_alerts = sorted(filtered_alerts, key=lambda x: x['timestamp'], reverse=True)
    
    return jsonify({
        'total': len(filtered_alerts),
        'alerts': filtered_alerts[:limit]
    })

@app.route('/api/alerts/<alert_id>', methods=['GET', 'PATCH'])
def alert_detail(alert_id):
    alert = next((a for a in alerts_db if a['alert_id'] == alert_id), None)
    
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    
    if request.method == 'PATCH':
        data = request.json
        if 'status' in data:
            alert['status'] = data['status']
        return jsonify(alert)
    
    return jsonify(alert)

@app.route('/api/threats')
def get_threats():
    severity_counts = {
        'CRITICAL': len([a for a in alerts_db if a['severity'] == 'CRITICAL']),
        'HIGH': len([a for a in alerts_db if a['severity'] == 'HIGH']),
        'MEDIUM': len([a for a in alerts_db if a['severity'] == 'MEDIUM']),
        'LOW': len([a for a in alerts_db if a['severity'] == 'LOW'])
    }
    
    threat_score = detection_engine.calculate_threat_score(alerts_db)
    
    return jsonify({
        'total_alerts': len(alerts_db),
        'severity_counts': severity_counts,
        'threat_score': threat_score,
        'open_alerts': len([a for a in alerts_db if a['status'] == 'OPEN']),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/resources')
def get_resources():
    try:
        buckets = detection_engine.cloudtrail_monitor.get_s3_buckets()
        
        instances = detection_engine.cloudtrail_monitor.get_ec2_instances()
        
        users = detection_engine.permission_analyzer.get_all_users()
        
        return jsonify({
            's3_buckets': buckets,
            'ec2_instances': instances,
            'iam_users': [{'UserName': u.get('UserName'), 'CreateDate': str(u.get('CreateDate'))} for u in users],
            'total_resources': len(buckets) + len(instances) + len(users)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
def get_logs():
    try:
        limit = int(request.args.get('limit', 50))
        events = detection_engine.cloudtrail_monitor.get_recent_events(max_results=limit)
        
        return jsonify({
            'total': len(events),
            'events': events
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan', methods=['POST'])
def trigger_scan():
    try:
        threats = []
        
        events = detection_engine.cloudtrail_monitor.get_recent_events(max_results=100)
        
        login_events = [e for e in events if e['EventName'] == 'ConsoleLogin']
        
        login_events.sort(key=lambda x: x.get('EventTime', datetime.now()))
        
        failed_attempts_by_ip = {}
        
        for login in login_events:
            username = login.get('Username', 'unknown')
            source_ip = login.get('SourceIPAddress', 'unknown')
            event_time = login.get('EventTime', datetime.now())
            error_code = login.get('ErrorCode')
            
            ct_event_str = login.get('CloudTrailEvent', '{}')
            ct_event = json.loads(ct_event_str) if isinstance(ct_event_str, str) else ct_event_str
            response_elements = ct_event.get('responseElements', {})
            
            is_failed = False
            if response_elements and 'ConsoleLogin' in str(response_elements):
                login_status = response_elements.get('ConsoleLogin', 'Success')
                is_failed = (login_status == 'Failure')
            elif error_code:
                is_failed = True
            
            if source_ip not in failed_attempts_by_ip:
                failed_attempts_by_ip[source_ip] = 0
            
            if is_failed:
                severity = 'HIGH'
                title = f'Failed Console Login: {username}'
                description = f'Failed login attempt from {source_ip}. Authentication failed.'
                if error_code:
                    description += f' Error: {error_code}'
                
                failed_attempts_by_ip[source_ip] += 1
            else:
                if failed_attempts_by_ip[source_ip] >= 2:
                    severity = 'CRITICAL'
                    title = f'SUSPICIOUS LOGIN: {username}'
                    description = f'Successful login from {source_ip} after {failed_attempts_by_ip[source_ip]} failed attempts! Possible brute force breach at {event_time}'
                else:
                    severity = 'LOW'
                    title = f'Console Login: {username}'
                    description = f'Successful login from {source_ip} at {event_time}'
                
                failed_attempts_by_ip[source_ip] = 0
            threats.append({
                'alert_id': str(uuid.uuid4()),
                'rule_id': 'CONSOLE-LOGIN',
                'severity': severity,
                'title': title,
                'description': description,
                'source_ip': source_ip,
                'user': username,
                'timestamp': event_time.isoformat() if hasattr(event_time, 'isoformat') else str(event_time),
                'raw_event': login,
                'auto_remediated': False,
                'status': 'OPEN'
            })
        
        buckets = detection_engine.cloudtrail_monitor.get_s3_buckets()
        
        for bucket in buckets:
            severity = 'LOW'
            description = f'Created: {bucket["CreationDate"]}, Encrypted: {bucket["Encrypted"]}, Versioning: {bucket["Versioning"]}, Public: {bucket["PublicAccess"]}'
            
            if bucket['PublicAccess']:
                severity = 'HIGH'
                description = 'WARNING: Bucket is publicly accessible! ' + description
            elif not bucket['Encrypted']:
                severity = 'MEDIUM'
                description = 'WARNING: Bucket is not encrypted! ' + description
            elif not bucket['Versioning']:
                severity = 'LOW'
                description = 'INFO: Versioning not enabled. ' + description
            
            threats.append({
                'alert_id': str(uuid.uuid4()),
                'rule_id': 'S3-BUCKET',
                'severity': severity,
                'title': f'S3 Bucket: {bucket["Name"]}',
                'description': description,
                'source_ip': 'N/A',
                'user': 'System Scan',
                'timestamp': bucket['CreationDate'].isoformat() if hasattr(bucket['CreationDate'], 'isoformat') else str(bucket['CreationDate']),
                'raw_event': bucket,
                'auto_remediated': False,
                'status': 'OPEN'
            })
        
        instances = detection_engine.cloudtrail_monitor.get_ec2_instances()
        
        for instance in instances:
            severity = 'LOW' if instance['State'] == 'stopped' else 'MEDIUM'
            description = f'Type: {instance["InstanceType"]}, State: {instance["State"]}, Launched: {instance["LaunchTime"]}'
            
            if instance['State'] == 'running':
                description = 'ACTIVE: Instance is running. ' + description
            else:
                description = 'STOPPED: Instance is not running. ' + description
            
            instance_display = f'{instance.get("InstanceName", "Unnamed")} ({instance["InstanceId"]})'
            
            threats.append({
                'alert_id': str(uuid.uuid4()),
                'rule_id': 'EC2-INSTANCE',
                'severity': severity,
                'title': f'EC2 Instance: {instance_display}',
                'description': description,
                'source_ip': 'N/A',
                'user': 'System Scan',
                'timestamp': instance['LaunchTime'].isoformat() if hasattr(instance['LaunchTime'], 'isoformat') else str(instance['LaunchTime']),
                'raw_event': instance,
                'auto_remediated': False,
                'status': 'OPEN'
            })
        
        users = detection_engine.permission_analyzer.get_all_users()
        
        for user in users:
            create_date = user.get('CreateDate', datetime.now())
            threats.append({
                'alert_id': str(uuid.uuid4()),
                'rule_id': 'IAM-USER',
                'severity': 'LOW',
                'title': f'IAM User: {user["UserName"]}',
                'description': f'User account created: {create_date}',
                'source_ip': 'N/A',
                'user': user['UserName'],
                'timestamp': create_date.isoformat() if hasattr(create_date, 'isoformat') else str(create_date),
                'raw_event': user,
                'auto_remediated': False,
                'status': 'OPEN'
            })
        
        cloudtrail_threats = detection_engine.analyze_cloudtrail_events(events)
        critical_threats = [t for t in cloudtrail_threats if t['severity'] in ['CRITICAL', 'HIGH'] and 'Login' not in t.get('title', '')]
        threats.extend(critical_threats)
        iam_threats = detection_engine.analyze_iam_permissions()
        threats.extend(iam_threats)
        
        global alerts_db
        alerts_db = []
        alerts_db.extend(threats)
        
        return jsonify({
            'status': 'success',
            'new_threats': len(threats),
            'total_alerts': len(alerts_db),
            's3_buckets': len(buckets),
            'ec2_instances': len(instances),
            'iam_users': len(users),
            'console_logins': len(login_events),
            'cloudtrail_events': len(events)
        })
    except Exception as e:
        logger.error(f"Scan error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/monitoring/start', methods=['POST'])
def start_monitoring():
    global monitoring_active, monitoring_thread
    
    if not monitoring_active:
        monitoring_active = True
        monitoring_thread = Thread(target=background_monitor, daemon=True)
        monitoring_thread.start()
        return jsonify({'status': 'started'})
    
    return jsonify({'status': 'already_running'})

@app.route('/api/monitoring/stop', methods=['POST'])
def stop_monitoring():
    global monitoring_active
    
    monitoring_active = False
    return jsonify({'status': 'stopped'})

@app.route('/api/clear', methods=['POST'])
def clear_alerts():
    global alerts_db
    alerts_db = []
    return jsonify({'status': 'cleared'})

@socketio.on('connect')
def handle_connect():
    logger.info("Client connected")
    emit('connection_response', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    logger.info("Client disconnected")

@socketio.on('start_monitoring')
def handle_start_monitoring():
    global monitoring_active, monitoring_thread
    
    if not monitoring_active:
        monitoring_active = True
        monitoring_thread = Thread(target=background_monitor, daemon=True)
        monitoring_thread.start()
        emit('monitoring_status', {'status': 'started'})
    else:
        emit('monitoring_status', {'status': 'already_running'})

@socketio.on('stop_monitoring')
def handle_stop_monitoring():
    global monitoring_active
    monitoring_active = False
    emit('monitoring_status', {'status': 'stopped'})

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
