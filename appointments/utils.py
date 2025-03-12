import boto3
import os
from dotenv import load_dotenv

load_dotenv()

def get_users_table():
    dynamodb = boto3.resource('dynamodb',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_DEFAULT_REGION'))
    return dynamodb.Table('Users')


def get_appointments_table():
    dynamodb = boto3.resource('dynamodb',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_DEFAULT_REGION'))
    return dynamodb.Table('Appointments')