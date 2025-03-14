import boto3
import os
from django.contrib import messages
from django.shortcuts import render, redirect
from boto3.dynamodb.conditions import Key
from .utils import get_users_table, get_appointments_table
from django.contrib.auth.hashers import check_password
import uuid
import json
import base64
import secrets
from datetime import datetime, timedelta
from sns_appointment_notification.notification.appointment import AppointmentNotification
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.hashers import make_password
from dotenv import load_dotenv
from botocore.exceptions import ClientError
from  appointments.scripts.cloud_watch import AppointmentMonitoring
import logging
logger = logging.getLogger(__name__)    

load_dotenv()


def home(request):
    return render(request, 'home.html')

def register(request):
    if request.method == 'POST':
        full_name = request.POST.get('full_name')
        email = request.POST.get('email')
        phone_number = request.POST.get('phone')
        gender = request.POST.get('gender')
        role = request.POST.get('role')
        specialization = request.POST.get('specialization', None)  # Only needed for doctors
        password = request.POST.get('password1')
        
        try:
            users_table = get_users_table()
            
            # Check if user exists
            user_exist = users_table.query(
                IndexName='EmailIndex',
                KeyConditionExpression=Key('email').eq(email)
            )
            if user_exist['Items']:
                return render(request, 'register.html', {"error": "Email already exists"})

            user_id = str(uuid.uuid4())
            hashed_password = make_password(password)
            
            users_table.put_item(Item={
                'user_id': user_id,
                'email': email,
                'password': hashed_password,
                'full_name': full_name,
                'phone_number': phone_number,
                'gender': gender,
                'role': role,
                'specialization': specialization,
                'is_active': True
            })
            if role == 'patient':
                notifier = AppointmentNotification()
                notifier.sns_client.subscribe_patient(email)
            elif role=='doctor':
               monitor = AppointmentMonitoring()
               monitor.create_alarm_for_rejected_appointments(user_id, email)
               messages.info(request, "Please check your email to confirm notifications for appointment activities.")

            
                
            messages.success(request, "Registration successful! Please login.")
            return redirect('login')

        except Exception as e:
            return render(request, 'register.html', {"error": str(e)})

    return render(request, 'register.html')

def login_page(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        users_table = get_users_table()
        try:
            response = users_table.query(
                IndexName='EmailIndex',
                KeyConditionExpression=Key('email').eq(email),
            )

            if response['Items'] and len(response['Items']) > 0:
                user = response['Items'][0]
                if check_password(password, user.get('password')):
                    request.session['user_id'] = user.get('user_id')
                    request.session['email'] = user.get('email')
                    request.session['is_authenticated'] = True
                    request.session['user_data'] = {
                            'user_id': user.get('user_id'),
                            'email': user.get('email'),
                            'full_name': user.get('full_name'),
                            'role': user.get('role'),
                            'gender': user.get('gender'),
                            'phone_number': user.get('phone_number'),
                            'specialization': user.get('specialization')
                        }
                    return redirect('dashboard')
            
            return render(request, "login.html", {"error": "Invalid credentials"})
        except Exception as e:
            return render(request, 'login.html', {"error": str(e)})
    return render(request, 'login.html')

def logout_view(request):
    request.session.flush()
    
    return redirect('home')

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        users_table = get_users_table()
        
        # Check if user exists
        existing = users_table.query(
            IndexName='EmailIndex',
            KeyConditionExpression=Key('email').eq(email)
        )
        
        if existing['Items']:
            user = existing['Items'][0]
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            expiry_time = (datetime.now() + timedelta(hours=24)).isoformat()
            
            # Update user record with reset token and expiry
            users_table.update_item(
                Key={'user_id': user['user_id']},
                UpdateExpression='SET reset_token = :token, reset_token_expiry = :expiry',
                ExpressionAttributeValues={
                    ':token': reset_token,
                    ':expiry': expiry_time
                }
            )
            
            # Send reset email
            reset_link = f"{request.scheme}://{request.get_host()}/reset-password/{reset_token}/"
            send_mail(
                'Password Reset Request',
                f'Click the following link to reset your password: {reset_link}',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            
            messages.success(request, "If an account exists with this email, you will receive password reset instructions.")
            return redirect('login')
        else:
            # Don't reveal if email exists or not
            messages.success(request, "If an account exists with this email, you will receive password reset instructions.")
            return redirect('login')
            
    return render(request, 'forgot_password.html')

def reset_password(request, reset_token):
    users_table = get_users_table()
    
    # Scan for user with this reset token
    response = users_table.scan(
        FilterExpression='reset_token = :token',
        ExpressionAttributeValues={':token': reset_token}
    )
    
    if not response['Items']:
        messages.error(request, "Invalid or expired reset token.")
        return redirect('login')
        
    user = response['Items'][0]
    
    # Check if token is expired
    if 'reset_token_expiry' in user:
        expiry_time = datetime.fromisoformat(user['reset_token_expiry'])
        if datetime.now() > expiry_time:
            messages.error(request, "Reset token has expired.")
            return redirect('login')
    
    if request.method == 'POST':
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        
        if password1 != password2:
            return render(request, 'reset_password.html', {'error': 'Passwords do not match'})
            
        # Update password and remove reset token
        hashed_password = make_password(password1)
        users_table.update_item(
            Key={'user_id': user['user_id']},
            UpdateExpression='SET password = :pass REMOVE reset_token, reset_token_expiry',
            ExpressionAttributeValues={':pass': hashed_password}
        )
        
        messages.success(request, "Password has been reset successfully. Please login with your new password.")
        return redirect('login')
        
    return render(request, 'reset_password.html')

def update_profile(request):
    if not request.session.get('is_authenticated', False):
        return redirect('login')
    
    user_data = request.session.get('user_data', {})
    
    if request.method == 'POST':
        full_name = request.POST.get('full_name')
        phone_number = request.POST.get('phone')
        gender = request.POST.get('gender')
        
        try:
            users_table = get_users_table()
            
            # Update the user in DynamoDB
            users_table.update_item(
                Key={'user_id': user_data['user_id']},
                UpdateExpression='SET full_name = :fn, phone_number = :ph, gender = :g',
                ExpressionAttributeValues={
                    ':fn': full_name,
                    ':ph': phone_number,
                    ':g': gender
                }
            )
            
            # Update session data
            user_data.update({
                'full_name': full_name,
                'phone_number': phone_number,
                'gender': gender
            })
            request.session['user_data'] = user_data
            
            messages.success(request, 'Profile updated successfully!')
            return redirect('dashboard')
            
        except Exception as e:
            return render(request, 'update_profile.html', {
                'error': str(e),
                'user_data': user_data
            })
    
    return render(request, 'update_profile.html', {'user_data': user_data})

def delete_account(request):
    if not request.session.get('is_authenticated', False):
        return redirect('login')
    
    if request.method == 'POST':
        try:
            # Get user data from session
            user_data = request.session.get('user_data', {})
            user_id = user_data.get('user_id')
            
            if not user_id:
                raise ValueError("User ID not found in session")
            
            # Initialize DynamoDB table
            users_table = get_users_table()
            
            # Remove user from DynamoDB
            users_table.delete_item(
                Key={
                    'user_id': user_id
                }
            )
            
            # Clear session data
            request.session.flush()
            
            # Add success message
            messages.success(request, "Your account has been successfully deleted.")
            return redirect('home')
            
        except Exception as e:
            messages.error(request, f"An error occurred while deleting your account: {str(e)}")
            return redirect('dashboard')
    
    # If not POST request, redirect to dashboard
    return redirect('dashboard')

def dashboard(request):
    if not request.session.get('is_authenticated', False):
        return redirect('login')
    
    try:
        user_data = request.session.get('user_data', {})
        users_table = get_users_table()
        
        if user_data.get('role') == 'doctor':
            appointments_table = get_appointments_table()
            response = appointments_table.query(
                IndexName='DoctorAppointmentsIndex',
                KeyConditionExpression=Key('doctor_id').eq(user_data['user_id'])
            )
            
            appointments = response.get('Items', [])
            
            context = {
                'user': {
                    'full_name': user_data.get('full_name', ''),
                    'email': user_data.get('email', ''),
                    'phone_number': user_data.get('phone_number', ''),
                    'gender': user_data.get('gender', ''),
                    'specialization': user_data.get('specialization', '')
                },
                'pending_appointments': [a for a in appointments if a['status'] == 'pending'],
                'approved_appointments': [a for a in appointments if a['status'] == 'approved'],
                'rejected_appointments': [a for a in appointments if a['status'] == 'rejected']
            }
            return render(request, 'doctordashboard.html', context)
        else:
            # Patient dashboard
            user_details = request.session.get('user_data',{})
            
            # Get all appointments for this user with a scan
            appointments_table = get_appointments_table()
            response = appointments_table.query(
            IndexName='UserAppointmentsIndex', 
            KeyConditionExpression=Key('user_id').eq(user_data['user_id'])
            )
            all_appointments = response.get('Items', [])
            
            # Filter for appointments with prescriptions
            appointments_with_prescriptions = [
                a for a in all_appointments if a.get('prescription_url')
            ]
            
            # Get doctors for booking section
            response = users_table.query(
            IndexName='RoleIndex',  
            KeyConditionExpression=Key('role').eq('doctor')
            )
            doctors = response.get('Items', [])
            
            context = {
                'user': {
                    'full_name': user_details.get('full_name', ''),
                    'email': user_details.get('email', ''),
                    'phone_number': user_details.get('phone_number', ''),
                    'gender': user_details.get('gender', ''),
                    'role': user_details.get('role', 'patient')
                },
                'doctors': doctors,
                'today_date': datetime.now().date().isoformat(),
                'appointments_with_prescriptions': appointments_with_prescriptions
            }
            return render(request, 'patientdashboard.html', context)
    except Exception as e:
        messages.error(request, f"Error loading dashboard: {str(e)}")
        return redirect('home')



def book_appointments(request):
    if not request.session.get('is_authenticated', False) or request.session['user_data']['role'] != 'patient':
        return redirect('login')

    if request.method == 'POST':
        try:
            # Get form data
            doctor_id = request.POST.get('doctor_id')
            appointment_date = request.POST.get('appointment_date')
            appointment_time = request.POST.get('appointment_time')
            reason = request.POST.get('reason', '')
            patient_id = request.session['user_data']['user_id']
            patient_name = request.session['user_data']['full_name']

            # Check date validity
            appointment_datetime = datetime.strptime(f"{appointment_date} {appointment_time}", "%Y-%m-%d %H:%M")
            if appointment_datetime < datetime.now():
                messages.error(request, "Cannot book appointments in the past")
                return redirect('dashboard')

            # Get doctor details
            users_table = get_users_table()
            doctor = users_table.get_item(Key={'user_id': doctor_id}).get('Item')

            appointments_table = get_appointments_table()
            # Create appointment
            appointment_id = str(uuid.uuid4())
            appointments_table.put_item(Item={
                'appointment_id': appointment_id,
                'user_id': patient_id,  # Range key (patient ID)
                'doctor_id': doctor_id,
                'patient_name': patient_name,
                'doctor_name': doctor['full_name'],
                'appointment_date': appointment_date,
                'appointment_time': appointment_time,
                'reason': reason,
                'status': 'pending',
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            })
            

            messages.success(request, "Appointment request sent successfully!")
            return redirect('dashboard')

        except Exception as e:
            print(f"Error in book_appointment: {str(e)}")
            messages.error(request, "Failed to book appointment. Please try again.")
            return redirect('dashboard')

    return redirect('dashboard')


def handle_appointment_status(request, appointment_id, status):
    if not request.session.get('is_authenticated', False):
        return redirect('login')
    
    try:
        appointments_table = get_appointments_table()
        
        # Use a scan operation with a filter instead of a query on a non-existent index
        response = appointments_table.scan(
            FilterExpression=Key('appointment_id').eq(appointment_id)
        )
        
        if not response['Items']:
            messages.error(request, "Appointment not found")
            return redirect('dashboard')
        
        appointment = response['Items'][0]
        user_id = appointment['user_id']
        doctor_id = appointment['doctor_id']

        # Update the appointment status
        appointments_table.update_item(
            Key={'appointment_id': appointment_id, 'user_id': user_id},
            UpdateExpression='SET #status = :status',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':status': status}
        )
        
        # Send notification
        notifier = AppointmentNotification()
        users_table = get_users_table()
        patient = users_table.get_item(Key={'user_id': user_id})['Item']
        
        # Log the appointment status change to CloudWatch
        monitor = AppointmentMonitoring()
        monitor.log_appointment_status_change(doctor_id, status)
        
        if status == 'approved':
            notifier.send_approval_notification(
                patient_email=patient['email'],
                doctor_name=request.session['user_data']['full_name'],
                appointment_date=appointment['appointment_date'],
                appointment_time=appointment['appointment_time']
            )
        else:
            reason = request.POST.get('reason', 'No reason provided')
            notifier.send_rejection_notification(
                patient_email=patient['email'],
                doctor_name=request.session['user_data']['full_name'],
                appointment_date=appointment['appointment_date'],
                appointment_time=appointment['appointment_time'],
                reason=reason
            )
        
        messages.success(request, f"Appointment {status} and patient notified")
        return redirect('dashboard')
        
    except Exception as e:
        messages.error(request, f"Error updating appointment: {str(e)}")
        return redirect('dashboard')
    
AWS_STORAGE_BUCKET_NAME = os.getenv('AWS_STORAGE_BUCKET_NAME')
ALLOWED_FILE_TYPES = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

import base64

def upload_prescription(request, appointment_id):
    if not request.session.get('is_authenticated', False) or request.session.get('user_data', {}).get('role') != 'doctor':
        return redirect('login')
    
    try:
        appointments_table = get_appointments_table()
        
        # First query using GSI
        response = appointments_table.query(
            IndexName='DoctorAppointmentsIndex',
            KeyConditionExpression=Key('doctor_id').eq(request.session['user_data']['user_id'])
        )
        
        # Filter results locally for the appointment ID
        matching_appointments = [
            item for item in response['Items']
            if item['appointment_id'] == appointment_id
        ]
        
        if not matching_appointments:
            messages.error(request, "Appointment not found or unauthorized")
            return redirect('dashboard')
            
        appointment = matching_appointments[0]
        user_id = appointment['user_id']

        # Get full item using primary key
        full_appointment = appointments_table.get_item(
            Key={
                'appointment_id': appointment_id,
                'user_id': user_id
            }
        ).get('Item')

        if not appointment:
            messages.error(request, "Appointment not found")
            return redirect('dashboard')

        # Verify doctor ownership
        if appointment.get('doctor_id') != request.session['user_data']['user_id']:
            messages.error(request, "Unauthorized access to appointment")
            return redirect('dashboard')

        # Check appointment status
        if appointment['status'] != 'approved':
            messages.error(request, "Cannot upload prescription for unapproved appointments")
            return redirect('dashboard')

        if request.method == 'POST' and request.FILES.get('prescription_file'):
            prescription_file = request.FILES['prescription_file']
            
            # File validation
            file_extension = prescription_file.name.split('.')[-1].lower()
            if file_extension not in ALLOWED_FILE_TYPES:
                messages.error(request, f"Invalid file type. Allowed types: {', '.join(ALLOWED_FILE_TYPES)}")
                return redirect('dashboard')
            
            if prescription_file.size > MAX_FILE_SIZE:
                messages.error(request, "File size exceeds 5MB limit")
                return redirect('dashboard')

            # Process file
            file_content = prescription_file.read()
            encoded_file_content = base64.b64encode(file_content).decode('utf-8')
            
            # Lambda invocation
            lambda_client = boto3.client('lambda')
            try:
                response = lambda_client.invoke(
                    FunctionName='upload_prescription_function',
                    InvocationType='RequestResponse',
                    Payload=json.dumps({
                        'appointment_id': appointment_id,
                        'user_id': appointment['user_id'],
                        'file_content': encoded_file_content,
                        'file_extension': file_extension,
                        'content_type': prescription_file.content_type
                    })
                )
            except ClientError as e:
                logger.error(f"AWS API error: {str(e)}")
                messages.error(request, "File service temporarily unavailable")
                return redirect('dashboard')

            result = json.loads(response['Payload'].read())
            
            # Debugging: Print the result from the Lambda function
            print(f"Lambda function result: {result}")
            
            if response['StatusCode'] == 200:
                body = json.loads(result.get('body', '{}'))
                if 'prescription_url' not in body:
                    logger.error("Missing prescription_url in Lambda response")
                    messages.error(request, "Failed to get prescription URL")
                    return redirect('dashboard')
                
                # Update DynamoDB
                appointments_table.update_item(
                    Key={'appointment_id': appointment_id, 'user_id': user_id},
                    UpdateExpression='SET prescription_url = :url, prescription_uploaded_at = :time',
                    ExpressionAttributeValues={
                        ':url': body['prescription_url'],
                        ':time': body.get('uploaded_at', datetime.now().isoformat())
                    }
                )

                # Send notification
                try:
                    users_table = get_users_table()
                    patient = users_table.get_item(Key={'user_id': appointment['user_id']})['Item']
                    AppointmentNotification().publish_uploaded_perscription(
                        patient_email=patient['email']
                    )
                    messages.success(request, "Prescription uploaded and patient notified")
                except Exception as e:
                    logger.error(f"Notification failed: {str(e)}")
                    messages.success(request, "Prescription uploaded (notification failed)")

            else:
                error_body = json.loads(result.get('body', '{}'))
                error_msg = error_body.get('error', 'Unknown error')
                logger.error(f"Lambda error: {error_msg}")
                messages.error(request, f"Upload failed: {error_msg}")

        return redirect('dashboard')

    except Exception as e:
        logger.error(f"Upload error: {str(e)}", exc_info=True)
        messages.error(request, "An unexpected error occurred")
        return redirect('dashboard')
    
def view_prescription(request, appointment_id):
    if not request.session.get('is_authenticated', False):
        return redirect('login')
    
    try:
        # Validate appointment ID
        try:
            uuid.UUID(appointment_id)
        except ValueError:
            messages.error(request, "Invalid appointment ID")
            return redirect('dashboard')

        # Get appointment
        appointments_table = get_appointments_table()
        user_id = request.session['user_data']['user_id']
        user_role = request.session['user_data'].get('role', 'patient')
        
        # Try to get the appointment directly first (this works for patients)
        if user_role == 'patient':
            # Patient is viewing their own prescription
            response = appointments_table.get_item(
                Key={
                    'appointment_id': appointment_id,
                    'user_id': user_id
                }
            )
            appointment = response.get('Item')
        else:
            # Doctor is viewing a prescription they created
            # First query using GSI to get user_id
            response = appointments_table.query(
                IndexName='DoctorAppointmentsIndex',
                KeyConditionExpression=Key('doctor_id').eq(user_id)
            )
            
            # Filter results locally for the appointment ID
            matching_appointments = [
                item for item in response['Items']
                if item['appointment_id'] == appointment_id
            ]
            
            if not matching_appointments:
                messages.error(request, "Appointment not found or unauthorized")
                return redirect('dashboard')
                
            appointment = matching_appointments[0]
            # Get full item using primary key
            response = appointments_table.get_item(
                Key={
                    'appointment_id': appointment_id,
                    'user_id': appointment['user_id']
                }
            )
            appointment = response.get('Item')
        
        # Check if we got an appointment
        if not appointment:
            messages.error(request, "Appointment not found")
            return redirect('dashboard')

        # Add debugging
        print(f"Found appointment: {appointment}")
        
        # Check prescription exists
        prescription_url = appointment.get('prescription_url')
        if not prescription_url:
            messages.error(request, "No prescription available")
            return redirect('dashboard')

        # Get presigned URL
        lambda_client = boto3.client('lambda')
        try:
            payload = json.dumps({'prescription_url': prescription_url})
            print(f"Calling Lambda with payload: {payload}")
            
            response = lambda_client.invoke(
                FunctionName='view_prescription_function',
                InvocationType='RequestResponse',
                Payload=payload
            )
        except ClientError as e:
            logger.error(f"AWS API error: {str(e)}")
            messages.error(request, "Prescription service unavailable")
            return redirect('dashboard')

        result = json.loads(response['Payload'].read())
        
        # Enhanced debugging
        print(f"Lambda StatusCode: {response['StatusCode']}")
        print(f"Lambda function result: {result}")
        
        if response['StatusCode'] == 200:
            body = json.loads(result.get('body', '{}')) if isinstance(result.get('body'), str) else result.get('body', {})
            presigned_url = body.get('presigned_url')
            
            if not presigned_url:
                messages.error(request, "Invalid prescription URL returned")
                return redirect('dashboard')
            
            print(f"Redirecting to presigned URL: {presigned_url}")
            response = redirect(presigned_url)
            # Security headers
            response['Content-Security-Policy'] = "default-src 'none'"
            response['X-Content-Type-Options'] = 'nosniff'
            return response
        else:
            error_body = json.loads(result.get('body', '{}')) if isinstance(result.get('body'), str) else result.get('body', {})
            error_message = error_body.get('error', 'Failed to view prescription')
            messages.error(request, f"Lambda error: {error_message}")
            return redirect('dashboard')

    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"View error: {str(e)}\n{error_details}")
        messages.error(request, f"Failed to view prescription: {str(e)}")
        return redirect('dashboard')