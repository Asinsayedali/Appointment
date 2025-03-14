from dotenv import load_dotenv
from botocore.exceptions import ClientError
import os 
import boto3

load_dotenv()


##client dynamodb
dynamodb = boto3.resource('dynamodb',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION')
)





appointments_table = dynamodb.create_table(
    TableName='Appointments',
    KeySchema=[
        {'AttributeName': 'appointment_id', 'KeyType': 'HASH'},
        {'AttributeName': 'user_id', 'KeyType': 'RANGE'}
    ],
    AttributeDefinitions=[
        {'AttributeName': 'appointment_id', 'AttributeType': 'S'},
        {'AttributeName': 'user_id', 'AttributeType': 'S'},
        {'AttributeName': 'doctor_id', 'AttributeType': 'S'}
    ],
    GlobalSecondaryIndexes=[
        {
            'IndexName': 'DoctorAppointmentsIndex',
            'KeySchema': [
                {'AttributeName': 'doctor_id', 'KeyType': 'HASH'}
            ],
            'Projection': {'ProjectionType': 'ALL'},
            'ProvisionedThroughput': {
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        },
        {
            'IndexName': 'UserAppointmentsIndex',  # ✅ New GSI for querying by user_id
            'KeySchema': [
                {'AttributeName': 'user_id', 'KeyType': 'HASH'}
            ],
            'Projection': {'ProjectionType': 'ALL'},
            'ProvisionedThroughput': {
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        }
    ],
    ProvisionedThroughput={
        'ReadCapacityUnits': 5,
        'WriteCapacityUnits': 5
    }
)
appointments_table.wait_until_exists()
print("Tables created successfully!")