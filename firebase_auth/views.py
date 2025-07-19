from django.shortcuts import render
from django.http import HttpResponse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
import firebase_admin
from firebase_admin import auth, credentials
from .models import FirebaseUser
from .firebase_init import initialize_firebase

# Initialize Firebase Admin SDK
initialize_firebase()


def index(request):
    return HttpResponse("Hello, world. You're at the polls index.")


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
