from dotenv import load_dotenv
import boto3
import os 

load_dotenv()

USER_POOL_ID = "us-east-1_G7lwWuP1G"  # Your actual User Pool ID

client = boto3.client('cognito-idp',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION'))

response = client.create_user_pool_client(
    UserPoolId=USER_POOL_ID,
    ClientName="DoctorAppointmentClient",
    GenerateSecret=False,  # For web apps (JS/SPA)
    RefreshTokenValidity=30,  # Days
    AccessTokenValidity=1,    # Hours
    IdTokenValidity=1,        # Hours
    ExplicitAuthFlows=[
        "ALLOW_USER_PASSWORD_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH"
    ],
    SupportedIdentityProviders=["COGNITO"],
    CallbackURLs=["http://localhost:8000/callback"],  # Update for production
    LogoutURLs=["http://localhost:8000/logout"],      # Update for production
    AllowedOAuthFlows=["code"],
    AllowedOAuthScopes=["email", "openid", "profile"],
    PreventUserExistenceErrors="ENABLED",
    TokenValidityUnits={
        "AccessToken": "hours",
        "IdToken": "hours",
        "RefreshToken": "days"
    }
)

client_id = response['UserPoolClient']['ClientId']
print(f"User Pool Client Created with ID: {client_id}")
print(f"Client Name: {response['UserPoolClient']['ClientName']}")
print(f"Created at: {response['UserPoolClient']['CreationDate']}")