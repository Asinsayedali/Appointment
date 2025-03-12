# src/sns_appointment_notification/notification/client.py
import boto3
import os
from typing import Optional

class SNSClient:
    def __init__(self, aws_access_key_id: Optional[str] = None,
                 aws_secret_access_key: Optional[str] = None,
                 region_name: Optional[str] = None):
        self.sns_client = boto3.client(
            'sns',
            aws_access_key_id=aws_access_key_id or os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=aws_secret_access_key or os.getenv('AWS_SECRET_ACCESS_KEY'),
            region_name=region_name or os.getenv('AWS_REGION', 'us-east-1')
        )
        self.topic_arn = os.getenv('SNS_TOPIC_ARN')

    def create_appointment_topic(self):
        """Create the appointments notification topic"""
        response = self.sns_client.create_topic(Name='AppointmentNotifications')
        self.topic_arn = response['TopicArn']
        return self.topic_arn

    def subscribe_patient(self, email: str):
        """Subscribe a patient to notifications"""
        return self.sns_client.subscribe(
            TopicArn=self.topic_arn,
            Protocol='email',
            Endpoint=email
        )

    def send_appointment_notification(self, email: str, message: str):
        """Send appointment status notification"""
        self.sns_client.publish(
            TopicArn=self.topic_arn,
            Message=message,
            Subject='Appointment Status Update',
            MessageAttributes={
                'email': {
                    'DataType': 'String',
                    'StringValue': email
                }
            }
        )

    def send_prescription_notification(self, patient_email:str, message:str):
        self.sns_client.publish(
            TopicArn=self.topic_arn,
            Message=message,
            Subject='Prescription Upload',
            MessageAttributes={
                'email': {
                    'DataType': 'String',
                    'StringValue': patient_email
                }
            }
        )