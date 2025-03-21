import boto3
import logging
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

class UserRegistrationMonitoring:
    def __init__(self):
        self.cloudwatch = boto3.client('cloudwatch',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            region_name=os.getenv('AWS_DEFAULT_REGION'))
        self.namespace = 'UserRegistrationSystem'

    def log_user_registration(self, user_id, user_email):
        """
        Log user registration events to CloudWatch
        """
        try:
            self.cloudwatch.put_metric_data(
                Namespace=self.namespace,
                MetricData=[
                    {
                        'MetricName': 'UserRegistered',
                        'Value': 1,
                        'Unit': 'Count',
                        'Dimensions': [
                            {
                                'Name': 'UserId',
                                'Value': user_id
                            },
                            {
                                'Name': 'UserEmail',
                                'Value': user_email
                            }
                        ],
                        'Timestamp': datetime.now()
                    }
                ]
            )
            logger.info(f"Logged registration for user {user_id} ({user_email})")
            return True
        except Exception as e:
            logger.error(f"Error logging registration to CloudWatch: {str(e)}")
            return False