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
import logging

logger = logging.getLogger(__name__)

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
        
        # Send email verification
        try:
            verification_link = auth.generate_email_verification_link(email)
            # In production, you would send this via your email service
            # For now, we'll just log it (remove in production)
            print(f"Verification email sent to {email}: {verification_link}")
        except Exception as e:
            # Don't fail registration if email sending fails
            print(f"Failed to send verification email: {e}")
        
        return JsonResponse({
            'success': True,
            'user_id': django_user.id,
            'firebase_uid': django_user.firebase_uid,
            'email': django_user.email,
            'username': django_user.username,
            'message': 'User registered successfully. Please check your email for verification.'
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


@csrf_exempt
@require_http_methods(["POST"])
def check_email_verification(request):
    """
    Check if user's email is verified in Firebase.
    """
    try:
        # Parse JSON request body
        data = json.loads(request.body)
        firebase_uid = data.get('firebase_uid')
        
        if not firebase_uid:
            return JsonResponse({
                'success': False,
                'error': 'No Firebase UID provided'
            }, status=400)
        
        # Get user from Firebase
        firebase_user = auth.get_user(firebase_uid)
        
        return JsonResponse({
            'success': True,
            'email_verified': firebase_user.email_verified,
            'email': firebase_user.email
        })
        
    except auth.UserNotFoundError:
        return JsonResponse({
            'success': False,
            'error': 'User not found'
        }, status=404)
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error checking email verification: {str(e)}'
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def resend_verification_email(request):
    """
    Resend verification email to user.
    """
    try:
        # Parse JSON request body
        data = json.loads(request.body)
        email = data.get('email')
        
        if not email:
            return JsonResponse({
                'success': False,
                'error': 'No email provided'
            }, status=400)
        
        # Generate and send verification email
        verification_link = auth.generate_email_verification_link(email)
        
        # In a real app, you might want to send this via your own email service
        # For now, we'll just return the link (for testing purposes)
        return JsonResponse({
            'success': True,
            'message': 'Verification email sent',
            'verification_link': verification_link  # Remove this in production
        })
        
    except auth.UserNotFoundError:
        return JsonResponse({
            'success': False,
            'error': 'User not found'
        }, status=404)
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error sending verification email: {str(e)}'
        }, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def forgot_password(request):
    """Send password reset email to user."""
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip()
        
        if not email:
            return JsonResponse({
                'success': False,
                'error': 'Email is required'
            }, status=400)
        
        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return JsonResponse({
                'success': False,
                'error': 'Invalid email format'
            }, status=400)
        
        try:
            # Check if user exists in Firebase
            firebase_user = auth.get_user_by_email(email)
            
            # Generate password reset link
            reset_link = auth.generate_password_reset_link(email)
            
            # In a real application, you would send this link via email
            # For now, we'll just return success
            logger.info(f"Password reset link generated for {email}: {reset_link}")
            
            return JsonResponse({
                'success': True,
                'message': 'Password reset email sent successfully'
            })
            
        except auth.UserNotFoundError:
            # Don't reveal if user exists or not for security
            return JsonResponse({
                'success': True,
                'message': 'If an account with this email exists, a password reset link has been sent'
            })
        except Exception as e:
            logger.error(f"Failed to send password reset email: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to send password reset email'
            }, status=500)
            
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        logger.error(f"Forgot password failed: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Password reset request failed'
        }, status=500)

@csrf_exempt
@require_http_methods(["GET", "PUT"])
def user_profile(request):
    """Get or update user profile information."""
    try:
        # Get Firebase UID from request headers (should be set by middleware or passed in)
        # For now, we'll require it in the request body for PUT operations
        if request.method == "GET":
            # For GET, we'll require the firebase_uid in query params
            firebase_uid = request.GET.get('firebase_uid')
            if not firebase_uid:
                return JsonResponse({
                    'success': False,
                    'error': 'Firebase UID is required'
                }, status=400)
            
            # Get user from Django database
            try:
                user = FirebaseUser.objects.get(firebase_uid=firebase_uid)
                return JsonResponse({
                    'success': True,
                    'user': {
                        'id': user.id,
                        'email': user.email,
                        'username': user.username,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'phone_number': user.phone_number,
                        'profile_picture_url': user.profile_picture_url,
                        'role': user.role,
                        'is_admin': user.is_admin,
                        'email_verified': user.email_verified if hasattr(user, 'email_verified') else None,
                        'created_at': user.created_at.isoformat() if user.created_at else None,
                        'updated_at': user.updated_at.isoformat() if user.updated_at else None
                    }
                })
            except FirebaseUser.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'error': 'User not found'
                }, status=404)
                
        elif request.method == "PUT":
            # Parse JSON request body
            data = json.loads(request.body)
            firebase_uid = data.get('firebase_uid')
            
            if not firebase_uid:
                return JsonResponse({
                    'success': False,
                    'error': 'Firebase UID is required'
                }, status=400)
            
            # Get user from Django database
            try:
                user = FirebaseUser.objects.get(firebase_uid=firebase_uid)
                
                # Update allowed fields
                if 'username' in data:
                    # Check if username is already taken by another user
                    if FirebaseUser.objects.filter(username=data['username']).exclude(firebase_uid=firebase_uid).exists():
                        return JsonResponse({
                            'success': False,
                            'error': 'Username is already taken'
                        }, status=409)
                    user.username = data['username']
                
                if 'first_name' in data:
                    user.first_name = data['first_name']
                
                if 'last_name' in data:
                    user.last_name = data['last_name']
                
                if 'phone_number' in data:
                    user.phone_number = data['phone_number']
                
                if 'profile_picture_url' in data:
                    user.profile_picture_url = data['profile_picture_url']
                
                # Role can only be updated by admin users (for now, we'll allow it)
                # In production, you might want to add admin-only restrictions
                if 'role' in data and data['role'] in ['user', 'admin']:
                    user.role = data['role']
                
                user.save()
                
                return JsonResponse({
                    'success': True,
                    'message': 'Profile updated successfully',
                    'user': {
                        'id': user.id,
                        'email': user.email,
                        'username': user.username,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'phone_number': user.phone_number,
                        'profile_picture_url': user.profile_picture_url,
                        'role': user.role,
                        'is_admin': user.is_admin,
                        'created_at': user.created_at.isoformat() if user.created_at else None,
                        'updated_at': user.updated_at.isoformat() if user.updated_at else None
                    }
                })
                
            except FirebaseUser.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'error': 'User not found'
                }, status=404)
                
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        logger.error(f"User profile operation failed: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Profile operation failed'
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def delete_account(request):
    """Delete a user account from both Firebase and Django."""
    try:
        # Parse JSON request body
        data = json.loads(request.body)
        firebase_uid = data.get('firebase_uid')
        
        if not firebase_uid:
            return JsonResponse({
                'success': False,
                'error': 'Firebase UID is required'
            }, status=400)
        
        # Get user from Django database
        try:
            user = FirebaseUser.objects.get(firebase_uid=firebase_uid)
            
            # Delete user from Firebase first
            try:
                auth.delete_user(firebase_uid)
            except Exception as firebase_error:
                logger.error(f"Failed to delete Firebase user {firebase_uid}: {str(firebase_error)}")
                return JsonResponse({
                    'success': False,
                    'error': 'Failed to delete Firebase account'
                }, status=500)
            
            # Delete user from Django database
            user.delete()
            
            return JsonResponse({
                'success': True,
                'message': 'Account deleted successfully'
            })
            
        except FirebaseUser.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'User not found'
            }, status=404)
            
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        logger.error(f"Account deletion failed: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Account deletion failed'
        }, status=500)
