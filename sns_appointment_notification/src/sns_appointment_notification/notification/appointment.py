# src/sns_appointment_notification/notification/appointment.py
from .client import SNSClient

class AppointmentNotification:
    def __init__(self):
        self.sns_client = SNSClient()
        if not self.sns_client.topic_arn:
            self.sns_client.create_appointment_topic()

    def send_approval_notification(self, patient_email: str, doctor_name: str, 
                                 appointment_date: str, appointment_time: str):
        message = f"""Your appointment with Dr. {doctor_name} 
                    on {appointment_date} at {appointment_time} 
                    has been approved!"""
        self.sns_client.send_appointment_notification(patient_email, message)

    def send_rejection_notification(self, patient_email: str, doctor_name: str, 
                                  appointment_date: str, appointment_time: str, 
                                  reason: str):
        message = f"""Your appointment with Dr. {doctor_name} 
                    on {appointment_date} at {appointment_time} 
                    has been rejected. Reason: {reason}"""
        self.sns_client.send_appointment_notification(patient_email, message)

    def publish_uploaded_perscription(self, patient_email:str):
        message = f"Prescription uploaded for patient {patient_email}"
        self.sns_client.send_prescription_notification(patient_email,message)