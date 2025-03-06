from dotenv import load_dotenv
import boto3
import os
load_dotenv()

# Initialize Cognito client
client = boto3.client('cognito-idp',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION'))

# Create User Pool with proper schema
response = client.create_user_pool(
    PoolName='DoctorAppointmentUserPool',
    Policies={
        'PasswordPolicy': {
            'MinimumLength': 8,
            'RequireUppercase': True,
            'RequireLowercase': True,
            'RequireNumbers': True,
            'RequireSymbols': False
        }
    },
    AutoVerifiedAttributes=['email'],
    Schema=[
        # Standard attributes
        {'Name': 'email', 'AttributeDataType': 'String', 'Required': True},
        {'Name': 'phone_number', 'AttributeDataType': 'String', 'Required': True},
        {'Name': 'name', 'AttributeDataType': 'String', 'Required': True},
        {'Name': 'gender', 'AttributeDataType': 'String', 'Required': True},
        
        # Custom attributes (NO 'custom:' prefix here)
        {'Name': 'role', 'AttributeDataType': 'String', 'Mutable': True, 'Required': False},
        {'Name': 'special', 'AttributeDataType': 'String', 'Mutable': True},
    ],
    EmailVerificationMessage="Your verification code is {####}",
    EmailVerificationSubject="Verify your email for Doctor Appointment",
)

user_pool_id = response['UserPool']['Id']
print(f"User Pool created with ID: {user_pool_id}")