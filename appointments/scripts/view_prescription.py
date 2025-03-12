import json
import boto3
import os
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    s3_client = boto3.client('s3')
    bucket_name = os.getenv('AWS_STORAGE_BUCKET_NAME')
    
    try:
        # Extract data from the event
        prescription_url = event['prescription_url']
        
        # Parse the URL to get S3 key
        s3_key = prescription_url.replace(f"https://{bucket_name}.s3.amazonaws.com/", "")
        if s3_key == prescription_url:
            region = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
            s3_key = prescription_url.replace(f"https://{bucket_name}.s3.{region}.amazonaws.com/", "")
        
        # Generate a pre-signed URL
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': s3_key},
            ExpiresIn=3600  # 1 hour
        )
        
        # Debugging: Print the presigned URL
        print(f"Presigned URL: {presigned_url}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({'presigned_url': presigned_url})
        }
    except ClientError as e:
        print(f"S3 Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f"S3 Error: {str(e)}"})
        }
    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }