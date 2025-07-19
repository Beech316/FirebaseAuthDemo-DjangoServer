import firebase_admin
from firebase_admin import credentials
from django.conf import settings
import os


def initialize_firebase():
    """
    Initialize Firebase Admin SDK with service account credentials.
    """
    try:
        # Check if Firebase is already initialized
        firebase_admin.get_app()
        return
    except ValueError:
        # Firebase not initialized, proceed with initialization
        pass
    
    # Get the path to the service account key
    service_account_path = settings.FIREBASE_SERVICE_ACCOUNT_KEY_PATH
    
    # Check if the service account file exists
    if not os.path.exists(service_account_path):
        raise FileNotFoundError(
            f"Firebase service account key not found at: {service_account_path}"
        )
    
    # Initialize Firebase Admin SDK
    cred = credentials.Certificate(service_account_path)
    firebase_admin.initialize_app(cred, {
        'projectId': settings.FIREBASE_PROJECT_ID,
    })
    
    print("Firebase Admin SDK initialized successfully!") 