# models.py
from django.contrib.auth.models import AbstractBaseUser

class DynamoDBUser(AbstractBaseUser):
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    def __init__(self, user_data):
        super().__init__()
        self.email = user_data['email']
        self.password = user_data['password']
        self.user_id = user_data['user_id']
        self.is_active = user_data.get('is_active', True)
        self.role = user_data.get('role', 'patient')
        self.full_name = user_data.get('full_name', '')
        self.gender = user_data.get('gender', '') 
        self.phone_number = user_data.get('phone_number', '')
        self.specialization = user_data.get('specialization')
        # Set a primary key attribute for Django
        self.pk = self.user_id
        self.id = self.user_id

    def __str__(self):
        return self.email

    def get_username(self):
        return self.email

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.user_id)
        
    # Override save method to prevent database operations
    def save(self, *args, **kwargs):
        # Do nothing - data is already in DynamoDB
        pass
        
    # Override delete method to prevent database operations
    def delete(self, *args, **kwargs):
        # Do nothing - we don't want to interact with Django's DB
        pass

    class Meta:
        managed = False  # Tell Django this isn't database-managed
        app_label = 'appointments'  # Match your Django app name
