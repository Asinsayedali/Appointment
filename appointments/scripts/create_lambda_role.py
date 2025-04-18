import boto3
import json
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def create_lambda_role(role_name):
    iam_client = boto3.client('iam',
                          aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                          aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
                          region_name=os.getenv('AWS_DEFAULT_REGION'))

    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    response = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(assume_role_policy_document),
        Description='Role for Lambda functions to access S3 and other AWS services'
    )

    # Attach the AWSLambdaBasicExecutionRole policy
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn='arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
    )

    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn='arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess'  # For DynamoDB access
    )

    return response['Role']['Arn']

if __name__ == "__main__":
    role_name = 'LambdaDynamoRole'
    role_arn = create_lambda_role(role_name)
    print(f"Created role with ARN: {role_arn}")
    
    # Save this to environment for future use
    with open('.env', 'a') as f:
        f.write(f"\nLAMBDA_ROLE_ARN={role_arn}")