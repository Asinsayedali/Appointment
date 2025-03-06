from dotenv import load_dotenv
from botocore.exceptions import ClientError
import os 
import boto3

load_dotenv()



dynamodb = boto3.resource('dynamodb',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION')
)

def create_tables():
    try:
        # Create Users Table with both GSIs (RoleIndex and EmailIndex)
        users_table = dynamodb.create_table(
            TableName='Users',
            KeySchema=[
                {'AttributeName': 'user_id', 'KeyType': 'HASH'}  # Primary key
            ],
            AttributeDefinitions=[
                {'AttributeName': 'user_id', 'AttributeType': 'S'},  # PK attribute
                {'AttributeName': 'role', 'AttributeType': 'S'},     # For RoleIndex
                {'AttributeName': 'email', 'AttributeType': 'S'}      # For EmailIndex
            ],
            GlobalSecondaryIndexes=[
                # RoleIndex GSI
                {
                    'IndexName': 'RoleIndex',
                    'KeySchema': [
                        {'AttributeName': 'role', 'KeyType': 'HASH'}
                    ],
                    'Projection': {'ProjectionType': 'ALL'},
                    'ProvisionedThroughput': {
                        'ReadCapacityUnits': 5,
                        'WriteCapacityUnits': 5
                    }
                },
                # EmailIndex GSI
                {
                    'IndexName': 'EmailIndex',
                    'KeySchema': [
                        {'AttributeName': 'email', 'KeyType': 'HASH'}
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
        users_table.meta.client.get_waiter('table_exists').wait(TableName='Users')
        print("Users table created successfully.")
    except Exception as e:
        print("Error creating table:", e)
        users_table.wait_until_exists()

        # Appointments Table (unchanged)
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
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )
        appointments_table.wait_until_exists()

        print("Tables created successfully!")
        return True

    except ClientError as e:
        print(f"Error creating tables: {e.response['Error']['Message']}")
        return False

if __name__ == '__main__':
    create_tables()
