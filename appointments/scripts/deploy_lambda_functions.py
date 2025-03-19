import boto3
import os
from zipfile import ZipFile
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def create_lambda_function(function_name, handler, role_arn, zip_file_path, runtime='python3.8'):
    client = boto3.client('lambda',
                          aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                          aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
                          region_name=os.getenv('AWS_DEFAULT_REGION'))
    
    with open(zip_file_path, 'rb') as f:
        zipped_code = f.read()
    
    response = client.create_function(
        FunctionName=function_name,
        Runtime=runtime,
        Role=role_arn,
        Handler=handler,
        Code=dict(ZipFile=zipped_code),
        Timeout=60,
        MemorySize=128,
        Publish=True
    )
    
    function_arn = response['FunctionArn']
    print(f"Created Lambda function: {function_name}")
    print(f"Function ARN: {function_arn}")
    
    return response

def zip_lambda_function(file_name, zip_file_name):
    with ZipFile(zip_file_name, 'w') as zipf:
        zipf.write(file_name)

if __name__ == "__main__":
    # Load environment variables
    load_dotenv()

    # Define the role ARN for the Lambda function
    role_arn = os.getenv('LAMBDA_ROLE_ARN')

    # Create and deploy the store appointment Lambda function
    zip_lambda_function('store_appointment.py', 'store_appointment.zip')
    create_lambda_function('store_appointment_function', 'store_appointment.lambda_handler', role_arn, 'store_appointment.zip')