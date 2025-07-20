from django.shortcuts import render
from django.http import HttpResponse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
import re
import firebase_admin
from firebase_admin import auth, credentials
from .models import FirebaseUser
from .firebase_init import initialize_firebase

# Initialize Firebase Admin SDK
initialize_firebase()


def validate_password_strength(password):
    """
    Validate password strength according to Firebase policy.
    Password must be at least 6 characters and contain:
    - At least 1 uppercase character
    - At least 1 special character
    - At least 1 numeric character
    """
    if len(password) < 6:
        return False, "Password must be at least 6 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least 1 uppercase character"
    
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        return False, "Password must contain at least 1 special character"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least 1 numeric character"
    
    return True, "Password meets strength requirements"


def index(request):
    return HttpResponse("Hello, world. You're at the polls index.")


@csrf_exempt
@require_http_methods(["POST"])
def register_user(request):
    """
    Register a new user with email and password.
    Creates user in Firebase and Django database.
    """
    try:
        # Parse JSON request body
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')
        username = data.get('username', '')
        first_name = data.get('first_name', '')
        last_name = data.get('last_name', '')
        
        # Validate required fields
        if not email or not password:
            return JsonResponse({
                'success': False,
                'error': 'Email and password are required'
            }, status=400)
        
        # Validate email format
        if '@' not in email:
            return JsonResponse({
                'success': False,
                'error': 'Invalid email format'
            }, status=400)
        
        # Validate password strength
        is_valid, error_message = validate_password_strength(password)
        if not is_valid:
            return JsonResponse({
                'success': False,
                'error': error_message
            }, status=400)
        
        # Check if user already exists in Django database
        if FirebaseUser.objects.filter(email=email).exists():
            return JsonResponse({
                'success': False,
                'error': 'User with this email already exists'
            }, status=409)
        
        # Create user in Firebase
        firebase_user = auth.create_user(
            email=email,
            password=password,
            display_name=f"{first_name} {last_name}".strip() if first_name or last_name else username,
            email_verified=False
        )
        
        # Create user in Django database
        django_user = FirebaseUser.objects.create(
            firebase_uid=firebase_user.uid,
            username=username or email.split('@')[0],
            email=email,
            first_name=first_name,
            last_name=last_name
        )
        
        # Send email verification (optional)
        # auth.generate_email_verification_link(email)
        
        return JsonResponse({
            'success': True,
            'user_id': django_user.id,
            'firebase_uid': django_user.firebase_uid,
            'email': django_user.email,
            'username': django_user.username,
            'message': 'User registered successfully'
        })
        
    except auth.EmailAlreadyExistsError:
        return JsonResponse({
            'success': False,
            'error': 'User with this email already exists in Firebase'
        }, status=409)
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Registration failed: {str(e)}'
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def verify_firebase_token(request):
    """
    Verify Firebase ID token and create/update user in Django database.
    """
    try:
        # Parse JSON request body
        data = json.loads(request.body)
        id_token = data.get('id_token')
        
        if not id_token:
            return JsonResponse({
                'success': False,
                'error': 'No ID token provided'
            }, status=400)
        
        # Verify the token with Firebase
        decoded_token = auth.verify_id_token(id_token)
        firebase_uid = decoded_token['uid']
        
        # Get or create user in Django database
        user, created = FirebaseUser.objects.get_or_create(
            firebase_uid=firebase_uid,
            defaults={
                'username': decoded_token.get('email', f'user_{firebase_uid}'),
                'email': decoded_token.get('email', ''),
                'first_name': decoded_token.get('name', '').split()[0] if decoded_token.get('name') else '',
                'last_name': ' '.join(decoded_token.get('name', '').split()[1:]) if decoded_token.get('name') else '',
            }
        )
        
        # Update user info if not newly created
        if not created:
            user.email = decoded_token.get('email', user.email)
            user.save()
        
        return JsonResponse({
            'success': True,
            'user_id': user.id,
            'firebase_uid': user.firebase_uid,
            'email': user.email,
            'username': user.username,
            'created': created
        })
        
    except auth.InvalidIdTokenError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid Firebase ID token'
        }, status=401)
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)
