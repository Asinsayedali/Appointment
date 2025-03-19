import boto3
import json
import os
from datetime import datetime
import uuid

def lambda_handler(event, context):
    """
    Lambda function to store appointment data in DynamoDB appointments table
    
    Expected event format:
    {
        "patient_id": "user_id_value",
        "doctor_id": "doctor_id_value",
        "patient_name": "patient_name_value",
        "doctor_name": "doctor_name_value",
        "appointment_date": "YYYY-MM-DD",
        "appointment_time": "HH:MM",
        "reason": "reason_text",
        "status": "pending"
    }
    """
    try:
        # Initialize DynamoDB resource
        dynamodb = boto3.resource('dynamodb')
        appointments_table = dynamodb.Table('Appointments')
        
        # Generate a UUID for the appointment
        appointment_id = str(uuid.uuid4())
        
        # Get current time for timestamps
        current_time = datetime.now().isoformat()
        
        # Create the item to insert
        appointment_item = {
            'appointment_id': appointment_id,
            'user_id': event['patient_id'],
            'doctor_id': event['doctor_id'],
            'patient_name': event['patient_name'],
            'doctor_name': event['doctor_name'],
            'appointment_date': event['appointment_date'],
            'appointment_time': event['appointment_time'],
            'reason': event.get('reason', ''),
            'status': 'pending',
            'created_at': current_time,
            'updated_at': current_time
        }
        
        # Store the item in DynamoDB
        appointments_table.put_item(Item=appointment_item)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Appointment created successfully',
                'appointment_id': appointment_id
            })
        }
        
    except Exception as e:
        print(f"Error saving appointment: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': f'Error creating appointment: {str(e)}'
            })
        }