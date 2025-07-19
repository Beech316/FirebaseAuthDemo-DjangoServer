# Firebase Authentication Demo - Django API

A Django REST API that handles Firebase authentication and user management.

## Quick Start

### Prerequisites
- Python 3.8+
- Firebase project with Authentication enabled

### Setup

1. **Get Firebase credentials:**
   - Go to [Firebase Console](https://console.firebase.google.com/)
   - Project Settings → Service Accounts → "Generate new private key"
   - Save as `api/firebase/serviceAccountKey.json`

2. **Install and run:**
   ```bash
   # Create virtual environment
   python -m venv .firebasedemoenv
   source .firebasedemoenv/bin/activate  # On Windows: .firebasedemoenv\Scripts\activate
   
   # Install dependencies
   pip install -r requirements.txt
   
   # Update Firebase project ID in firebasedemo/settings.py
   FIREBASE_PROJECT_ID = 'your-firebase-project-id'
   
   # Run migrations
   python manage.py makemigrations
   python manage.py migrate
   
   # Start server
   python manage.py runserver 0.0.0.0:8000
   ```

## API Endpoints

### `POST /auth/verify-token/`
Verifies Firebase ID token and creates/updates user.

---

**Note:** This is a demonstration project. For production, implement proper security measures. 