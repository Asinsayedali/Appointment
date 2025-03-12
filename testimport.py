try:
    from sns_appointment_notification.notification.appointment import AppointmentNotification
    print("Import successful!")
    print("AppointmentNotification class imported correctly")
except ImportError as e:
    print(f"Import error: {e}")
    
    # Try to import the package itself to see if it's available
    try:
        import sns_appointment_notification
        print(f"Package found at: {sns_appointment_notification.__file__}")
        print(f"Package contains: {dir(sns_appointment_notification)}")
    except ImportError:
        print("Package not found at all")