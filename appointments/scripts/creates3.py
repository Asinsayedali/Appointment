import boto3
from botocore.exceptions import ClientError
import os
from dotenv import load_dotenv
load_dotenv()

def create_bucket(bucket_name):
    try:
        s3_client =boto3.client('s3',
                                aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                                aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'))
        
        s3_client.create_bucket(Bucket=bucket_name)
    except ClientError as e:
        print(f"An error occurred: {e}")
        return False
    return True


def upload_file_object(file_obj, bucket, object_key=None):
    """
    Upload a file-like object to S3
    
    Args:
        file_obj: The file-like object to upload
        bucket: The S3 bucket name
        object_key: The S3 object key (filename in bucket)
        
    Returns:
        The S3 object key if successful, False otherwise
    """
    if object_key is None:
        object_key = file_obj.name
        
    s3_client = boto3.client('s3',
                         aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                         aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'))
    try:
        s3_client.upload_fileobj(file_obj, bucket, object_key)
        return object_key
    except ClientError as e:
        print(f"An error occurred: {e}")
        return False

def generate_presigned_url(bucket_name, object_key, expiration=3600):
    """
    Generate a presigned URL for downloading an object
    
    Args:
        bucket_name: The S3 bucket name
        object_key: The S3 object key
        expiration: URL expiration time in seconds (default 1 hour)
        
    Returns:
        The presigned URL string if successful, None otherwise
    """
    s3_client = boto3.client('s3',
                         aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                         aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'))
    try:
        response = s3_client.generate_presigned_url('get_object',
                                                Params={'Bucket': bucket_name,
                                                        'Key': object_key},
                                                ExpiresIn=expiration)
        return response
    except ClientError as e:
        print(f"Error generating presigned URL: {e}")
        return None


