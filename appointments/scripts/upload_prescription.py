import json
import boto3
import os
import base64
from datetime import datetime
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    bucket_name = os.environ['AWS_STORAGE_BUCKET_NAME']
    
    try:
        # Validate required parameters
        required_fields = ['appointment_id', 'user_id', 'file_content', 'file_extension']
        for field in required_fields:
            if field not in event:
                raise ValueError(f"Missing required field: {field}")
        
        # Decode file content
        file_content = base64.b64decode(event['file_content'])
        
        # Create S3 key with folder structure
        file_key = f"prescriptions/{event['user_id']}/{event['appointment_id']}.{event['file_extension']}"
        
        # Upload to S3
        s3.put_object(
            Bucket=bucket_name,
            Key=file_key,
            Body=file_content,
            ContentType=event.get('content_type', 'application/octet-stream'),
            ContentDisposition=f'inline; filename="{event['appointment_id']}-prescription.{event['file_extension']}"'
        )
        
        # Generate URL
        prescription_url = f"https://{bucket_name}.s3.amazonaws.com/{file_key}"
        
        # Debugging: Print the prescription URL
        print(f"Prescription URL: {prescription_url}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'prescription_url': prescription_url,
                's3_key': file_key,
                'uploaded_at': datetime.now().isoformat()
            })
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