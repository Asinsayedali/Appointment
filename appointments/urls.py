from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login_page, name='login'),
    path('register/', views.register, name='register'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('logout/', views.logout_view, name='logout'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/<str:reset_token>/', views.reset_password, name='reset_password'),
    path('update-profile/', views.update_profile, name='update_profile'),
    path('delete-account/', views.delete_account, name='delete_account'),
    path('book-appointments/', views.book_appointments, name='book_appointments'),
    path('appointment/<str:appointment_id>/approve/', views.handle_appointment_status, {'status': 'approved'}, name='approve_appointment'),
    path('appointment/<str:appointment_id>/reject/', views.handle_appointment_status, {'status': 'rejected'}, name='reject_appointment'),
    path('upload-prescription/<str:appointment_id>/', views.upload_prescription, name='upload_prescription'),
    path('view-prescription/<str:appointment_id>/', views.view_prescription, name='view_prescription'),
]
    
