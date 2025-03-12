import boto3
import os
from zipfile import ZipFile
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Modify create_lambda_function in deploy_lambda_functions.py
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
        Timeout=300,
        MemorySize=128,
        Publish=True,
        Environment={  # Add this section
            'Variables': {
                'AWS_STORAGE_BUCKET_NAME': os.getenv('AWS_STORAGE_BUCKET_NAME'),
            }
        }
    )
    return response

def zip_lambda_function(file_name, zip_file_name):
    with ZipFile(zip_file_name, 'w') as zipf:
        zipf.write(file_name)

if __name__ == "__main__":
    # Load environment variables
    load_dotenv()

    # Print environment variables for debugging
    print("AWS_ACCESS_KEY_ID:", os.getenv('AWS_ACCESS_KEY_ID'))
    print("AWS_SECRET_ACCESS_KEY:", os.getenv('AWS_SECRET_ACCESS_KEY'))
    print("AWS_DEFAULT_REGION:", os.getenv('AWS_DEFAULT_REGION'))
    print("LAMBDA_ROLE_ARN:", os.getenv('LAMBDA_ROLE_ARN'))

    # Print the current working directory
    print("Current working directory:", os.getcwd())

    # List the files in the current directory
    print("Files in the current directory:", os.listdir())

    # Define the role ARN for the Lambda function
    role_arn = os.getenv('LAMBDA_ROLE_ARN')

    # Create and deploy the upload prescription Lambda function
    zip_lambda_function('upload_prescription.py', 'upload_prescription.zip')
    create_lambda_function('upload_prescription_function', 'upload_prescription.lambda_handler', role_arn, 'upload_prescription.zip')

    # Create and deploy the view prescription Lambda function
    
    zip_lambda_function('view_prescription.py', 'view_prescription.zip')
    create_lambda_function('view_prescription_function', 'view_prescription.lambda_handler', role_arn, 'view_prescription.zip')

