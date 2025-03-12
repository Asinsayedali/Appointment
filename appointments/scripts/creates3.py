import boto3
import os
from dotenv import load_dotenv
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_s3_bucket():
    # Load environment variables from .env file
    load_dotenv()
    
    # Get AWS credentials and region from environment variables
    aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    aws_region = os.getenv('AWS_DEFAULT_REGION')
    bucket_name = os.getenv('AWS_STORAGE_BUCKET_NAME')
    print(bucket_name)
    # Validate required environment variables
    if not all([aws_access_key_id, aws_secret_access_key, aws_region, bucket_name]):
        logger.error("Missing required environment variables. Please check your .env file.")
        logger.info("Required variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, AWS_STORAGE_BUCKET_NAME")
        return False
    
    try:
        # Initialize S3 client
        s3_client = boto3.client(
            's3',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=aws_region
        )
        
        # Check if bucket already exists
        try:
            s3_client.head_bucket(Bucket=bucket_name)
            logger.info(f"Bucket '{bucket_name}' already exists. No action needed.")
            return True
        except:
            # Bucket doesn't exist, proceed with creation
            pass
        
        # Create the bucket
        if aws_region == 'us-east-1':
            # Special case for us-east-1 region
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            # For other regions, specify LocationConstraint
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={
                    'LocationConstraint': aws_region
                }
            )
        
        logger.info(f"Bucket '{bucket_name}' created successfully in region '{aws_region}'.")
        
        # Configure bucket for website hosting (if needed for direct file access)
        s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                'ErrorDocument': {'Key': 'error.html'},
                'IndexDocument': {'Suffix': 'index.html'}
            }
        )
        logger.info(f"Configured bucket for website hosting.")
        
        # Set bucket policy to allow public read access for prescriptions
        bucket_policy = {
            'Version': '2012-10-17',
            'Statement': [{
                'Sid': 'PublicReadForPrescriptions',
                'Effect': 'Allow',
                'Principal': '*',
                'Action': ['s3:GetObject'],
                'Resource': f'arn:aws:s3:::{bucket_name}/prescriptions/*'
            }]
        }
        
        # Convert policy to JSON string
        import json
        bucket_policy_string = json.dumps(bucket_policy)
        
        # Apply the policy
        s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=bucket_policy_string
        )
        logger.info(f"Applied bucket policy to allow public read access for prescriptions.")
        
        # Set CORS configuration to allow browser access
        cors_configuration = {
            'CORSRules': [{
                'AllowedHeaders': ['*'],
                'AllowedMethods': ['GET', 'HEAD'],
                'AllowedOrigins': ['*'],
                'ExposeHeaders': ['ETag'],
                'MaxAgeSeconds': 3000
            }]
        }
        
        s3_client.put_bucket_cors(
            Bucket=bucket_name,
            CORSConfiguration=cors_configuration
        )
        logger.info(f"Configured CORS settings for browser access.")
        
        return True
        
    except Exception as e:
        logger.error(f"Error creating S3 bucket: {str(e)}")
        return False

if __name__ == "__main__":
    logger.info("Starting S3 bucket creation script...")
    if create_s3_bucket():
        logger.info("S3 bucket setup completed successfully!")
    else:
        logger.error("Failed to set up S3 bucket. Check logs for details.")