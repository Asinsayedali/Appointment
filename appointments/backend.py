from django.contrib.auth.backends import BaseBackend
import boto3
from boto3.dynamodb.conditions import Key
from .models import DynamoDBUser  # Import from models.py
from .utils import get_users_table
from django.contrib.auth.hashers import check_password

class DynamoDBAuthBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            table = get_users_table()
            response = table.query(
                IndexName='EmailIndex',
                KeyConditionExpression=Key('email').eq(username)
            )
            
            if not response['Items']:
                return None
                
            user_data = response['Items'][0]
            
            if check_password(password, user_data['password']):
                return DynamoDBUser(user_data)
                
            return None
        except Exception as e:
            print(f"Authentication error: {str(e)}")
            return None

    def get_user(self, user_id):
        try:
            table = get_users_table()
            response = table.get_item(Key={'user_id': user_id})
            if 'Item' in response:
                return DynamoDBUser(response['Item'])
            return None
        except Exception as e:
            print(f"Get user error: {str(e)}")
            return None