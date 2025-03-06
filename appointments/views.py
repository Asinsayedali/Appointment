import boto3
import os
from django.contrib import messages
from django.shortcuts import render, redirect
from boto3.dynamodb.conditions import Key
from django.http import JsonResponse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# AWS Clients
cognito_client = boto3.client('cognito-idp', aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION'))
dynamodb = boto3.resource('dynamodb', aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION'))

users_table = dynamodb.Table('Users')  # Ensure this matches your DynamoDB table

# Cognito User Pool details
USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
USER_POOL_CLIENT_ID = os.getenv("COGNITO_USER_POOL_CLIENT_ID")

def home(request):
    return render(request, 'home.html')

def login_page(request):
    return render(request, 'login.html')

def register(request):
    if request.method == 'POST':
        print(request.POST.get('password1'))
        full_name = request.POST.get('full_name')
        email = request.POST.get('email')
        phone_number = request.POST.get('phone')
        gender = request.POST.get('gender')
        role = request.POST.get('role')
        specialization = request.POST.get('specialization', None)  # Only needed for doctors
        password = request.POST.get('password1')

        print(password)

        try:
            # Register user in AWS Cognito
            cognito_client.sign_up(
                ClientId=USER_POOL_CLIENT_ID,
                Username=email,
                Password=password,
                UserAttributes=[
                    {"Name": "email", "Value": email},
                    {"Name": "phone_number", "Value": phone_number},
                    {"Name": "name", "Value": full_name},
                    {"Name": "gender", "Value": gender},
                    {"Name": "custom:role", "Value": role},
                ] + ([{"Name": "custom:special", "Value": specialization}] if role == "doctor" else [])
            )
            request.session['pending_user'] = {
                'email': email,
                'full_name': full_name,
                'phone_number': phone_number,
                'gender': gender,
                'role': role,
                'specialization': specialization
            }
            request.session.set_expiry(900)  # 15 minute expiration
            
            return redirect('confirm_email')

        except cognito_client.exceptions.UsernameExistsException:
            return render(request, 'register.html', {"error": "User already exists."})
        except Exception as e:
            return render(request, 'register.html', {"error": str(e)})

    return render(request, 'register.html')
def confirm_email(request):
    # Get session data
    user_data = request.session.get('pending_user')
    
    if not user_data:
        return redirect('register')  # No pending registration
    
    email = user_data['email']
    
    if request.method == 'POST':
        try:
            code = request.POST.get('code', '').strip()
            if not code:
                raise ValueError("Verification code is required")
                
            # Confirm signup with Cognito
            response = cognito_client.confirm_sign_up(
                ClientId=USER_POOL_CLIENT_ID,
                Username=email,
                ConfirmationCode=code
            )
            
            # Get Cognito user ID
            user_data_response = cognito_client.admin_get_user(
                UserPoolId=USER_POOL_ID,
                Username=email
            )
            cognito_user_id = next(
                attr["Value"] for attr in user_data_response["UserAttributes"] 
                if attr["Name"] == "sub"
            )

            # Store in DynamoDB
            users_table.put_item(
                Item={
                    "user_id": cognito_user_id,
                    **user_data  # Spread all session data
                }
            )
            
            # Clear session data
            del request.session['pending_user']
            messages.success(request, "User registered succesfully! you can login now.")
            return redirect('login')

        except Exception as e:
            return render(request, 'confirm_email.html', {
                'error': str(e),
                'email': email  # Pass email for template context
            })
    
    return render(request, 'confirm_email.html', {'email': email})

def login_page(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()

        try:
            # 1. Cognito Authentication
            auth_response = cognito_client.initiate_auth(
                ClientId=USER_POOL_CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': email,
                    'PASSWORD': password
                }
            )

            # 2. Get Cognito User ID
            access_token = auth_response['AuthenticationResult']['AccessToken']
            user_info = cognito_client.get_user(AccessToken=access_token)
            cognito_user_id = next(
                attr['Value'] for attr in user_info['UserAttributes'] 
                if attr['Name'] == 'sub'
            )

            # 3. Query DynamoDB using GSI
            response = users_table.query(
                IndexName='EmailIndex',
                KeyConditionExpression=Key('email').eq(email)
            )

            if not response['Items']:
                raise Exception("User not found in database")

            user_data = response['Items'][0]

            # 4. Verify user_id matches
            if user_data['user_id'] != cognito_user_id:
                raise Exception("Security violation: User ID mismatch")

            # 5. Store session data
            request.session['user'] = {
                'user_id': user_data['user_id'],
                'email': email,
                'full_name': user_data['full_name'],
                'role': user_data['role'],
                'specialization': user_data.get('specialization')
            }

            return redirect('dashboard')

        except Exception as e:
            # Handle errors
            return render(request, 'login.html', {'error': str(e)})

    return render(request, 'login.html')

def logout(request):
    # Clear session data
    request.session.flush()
    return redirect('login')

def dashboard(request):
    user = request.session.get('user')
    if not user:
        return redirect('login')
    
    context = {
        'user': user,
        'is_doctor': user.get('role') == 'doctor'
    }
    return render(request, 'dashboard.html', context)

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        try:
            # Initiate password reset
            response = cognito_client.forgot_password(
                ClientId=USER_POOL_CLIENT_ID,
                Username=email
            )
            request.session['reset_email'] = email
            return redirect('reset_password')
        
        except cognito_client.exceptions.UserNotFoundException:
            error = "User with this email does not exist"
        except cognito_client.exceptions.InvalidParameterException:
            error = "Please enter a valid email address"
        except Exception as e:
            error = f"Error initiating password reset: {str(e)}"
        
        return render(request, 'forgot_password.html', {'error': error})
    
    return render(request, 'forgot_password.html')

def reset_password(request):
    email = request.session.get('reset_email')
    if not email:
        return redirect('forgot_password')
    
    if request.method == 'POST':
        code = request.POST.get('code', '').strip()
        new_password = request.POST.get('new_password', '').strip()
        confirm_password = request.POST.get('confirm_password', '').strip()

        if new_password != confirm_password:
            return render(request, 'reset_password.html', 
                         {'error': "Passwords do not match", 'email': email})

        try:
            # Confirm password reset
            response = cognito_client.confirm_forgot_password(
                ClientId=USER_POOL_CLIENT_ID,
                Username=email,
                ConfirmationCode=code,
                Password=new_password
            )
            del request.session['reset_email']
            messages.success(request, "Password reset succesfully!!")
            return redirect('login')
        
        except cognito_client.exceptions.CodeMismatchException:
            error = "Invalid verification code"
        except cognito_client.exceptions.ExpiredCodeException:
            error = "Verification code has expired"
        except Exception as e:
            error = f"Password reset failed: {str(e)}"
        
        return render(request, 'reset_password.html', 
                    {'error': error, 'email': email})
    
    return render(request, 'reset_password.html', {'email': email})