import boto3
import logging
import json
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

class AppointmentMonitoring:
    def __init__(self):
        self.cloudwatch = boto3.client('cloudwatch',aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION'))
        self.namespace = 'DoctorAppointmentSystem'

    def log_appointment_created(self, doctor_id):
        """
        Log appointment creation to CloudWatch
        """
        try:
            self.cloudwatch.put_metric_data(
                Namespace=self.namespace,
                MetricData=[
                    {
                        'MetricName': 'AppointmentsCreated',
                        'Value': 1,
                        'Unit': 'Count',
                        'Dimensions': [
                            {
                                'Name': 'DoctorId',
                                'Value': doctor_id
                            }
                        ],
                        'Timestamp': datetime.now()
                    }
                ]
            )
            logger.info(f"Logged appointment creation for doctor {doctor_id}")
        except Exception as e:
            logger.error(f"Error logging to CloudWatch: {str(e)}")

    def log_appointment_status_change(self, doctor_id, status):
        """
        Log appointment status changes to CloudWatch
        """
        try:
            self.cloudwatch.put_metric_data(
                Namespace=self.namespace,
                MetricData=[
                    {
                        'MetricName': f'Appointments{status.capitalize()}',
                        'Value': 1,
                        'Unit': 'Count',
                        'Dimensions': [
                            {
                                'Name': 'DoctorId',
                                'Value': doctor_id
                            }
                        ],
                        'Timestamp': datetime.now()
                    }
                ]
            )
            logger.info(f"Logged appointment {status} for doctor {doctor_id}")
        except Exception as e:
            logger.error(f"Error logging to CloudWatch: {str(e)}")

    def create_doctor_dashboard(self, doctor_id, doctor_name):
        """
        Create a CloudWatch dashboard for a specific doctor
        """
        try:
            dashboard_name = f"Doctor-{doctor_id}"
            dashboard_body = {
                "widgets": [
                    {
                        "type": "metric",
                        "x": 0,
                        "y": 0,
                        "width": 12,
                        "height": 6,
                        "properties": {
                            "metrics": [
                                [self.namespace, "AppointmentsCreated", "DoctorId", doctor_id],
                                [self.namespace, "AppointmentsApproved", "DoctorId", doctor_id],
                                [self.namespace, "AppointmentsRejected", "DoctorId", doctor_id]
                            ],
                            "view": "timeSeries",
                            "stacked": False,
                            "region": "us-east-1",  # Replace with your region
                            "title": f"Appointments for Dr. {doctor_name}",
                            "period": 86400
                        }
                    }
                ]
            }
            
            response = self.cloudwatch.put_dashboard(
            DashboardName=dashboard_name,
            DashboardBody=json.dumps(dashboard_body)
            )
            logger.info(f"Dashboard created with response: {response}")
            return f"https://console.aws.amazon.com/cloudwatch/home?region={os.getenv('AWS_DEFAULT_REGION', 'us-east-1')}#dashboards:name={dashboard_name}"
        except Exception as e:
            logger.error(f"Error creating CloudWatch dashboard: {str(e)}")
            return None

    def create_alarm_for_rejected_appointments(self, doctor_id, doctor_email):
        """
        Create an alarm that triggers when a doctor rejects too many appointments
        """
        try:
            alarm_name = f"TooManyRejections-{doctor_id}"
            
            # Create an SNS topic for the alarm
            sns = boto3.client('sns')
            topic = sns.create_topic(Name=f"appointment-alarms-{doctor_id}")
            topic_arn = topic['TopicArn']
            
            # Subscribe doctor to the SNS topic
            sns.subscribe(
                TopicArn=topic_arn,
                Protocol='email',
                Endpoint=doctor_email
            )
            
            # Create the alarm
            self.cloudwatch.put_metric_alarm(
                AlarmName=alarm_name,
                ComparisonOperator='GreaterThanThreshold',
                EvaluationPeriods=1,
                MetricName='AppointmentsRejected',
                Namespace=self.namespace,
                Period=86400,  # 1 day
                Statistic='Sum',
                Threshold=5,  # Alert if more than 5 rejections in a day
                ActionsEnabled=True,
                AlarmDescription='Alert when a doctor rejects too many appointments',
                AlarmActions=[topic_arn],
                Dimensions=[
                    {
                        'Name': 'DoctorId',
                        'Value': doctor_id
                    }
                ]
            )
            
            logger.info(f"Created rejection alarm for doctor {doctor_id}")
            return alarm_name
        except Exception as e:
            logger.error(f"Error creating CloudWatch alarm: {str(e)}")
            return None