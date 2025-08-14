from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
import json
from unittest.mock import patch, MagicMock
from .models import FirebaseUser

User = get_user_model()

class RegistrationTestCase(TestCase):
    """Test cases for the registration endpoint."""
    
    def setUp(self):
        """Set up test client and base data."""
        self.client = Client()
        self.registration_url = reverse('register_user')
        self.test_user_data = {
            "email": "test@example.com",
            "password": "TestPass123!",
            "username": "testuser",
            "first_name": "Test",
            "last_name": "User"
        }
    
    @patch('firebase_admin.auth.create_user')
    def test_successful_registration(self, mock_create_user):
        """Test successful user registration."""
        # Mock Firebase user creation
        mock_firebase_user = MagicMock()
        mock_firebase_user.uid = "test_firebase_uid_123"
        mock_create_user.return_value = mock_firebase_user
        
        # Make registration request
        response = self.client.post(
            self.registration_url,
            data=json.dumps(self.test_user_data),
            content_type='application/json'
        )
        
        # Check response
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertTrue(response_data['success'])
        self.assertEqual(response_data['email'], self.test_user_data['email'])
        self.assertEqual(response_data['username'], self.test_user_data['username'])
        self.assertIn('user_id', response_data)
        self.assertIn('firebase_uid', response_data)
        
        # Check that user was created in Django database
        self.assertTrue(FirebaseUser.objects.filter(email=self.test_user_data['email']).exists())
        django_user = FirebaseUser.objects.get(email=self.test_user_data['email'])
        self.assertEqual(django_user.firebase_uid, "test_firebase_uid_123")
        self.assertEqual(django_user.username, self.test_user_data['username'])
        self.assertEqual(django_user.first_name, self.test_user_data['first_name'])
        self.assertEqual(django_user.last_name, self.test_user_data['last_name'])
        
        # Verify Firebase was called correctly
        mock_create_user.assert_called_once_with(
            email=self.test_user_data['email'],
            password=self.test_user_data['password'],
            display_name=f"{self.test_user_data['first_name']} {self.test_user_data['last_name']}".strip(),
            email_verified=False
        )
    
    def test_missing_email(self):
        """Test registration with missing email."""
        data = {"password": "TestPass123!"}
        response = self.client.post(
            self.registration_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Email and password are required', response_data['error'])
    
    def test_missing_password(self):
        """Test registration with missing password."""
        data = {"email": "test@example.com"}
        response = self.client.post(
            self.registration_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Email and password are required', response_data['error'])
    
    def test_invalid_email_format(self):
        """Test registration with invalid email format."""
        data = {
            "email": "invalid-email",
            "password": "TestPass123!"
        }
        response = self.client.post(
            self.registration_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Invalid email format', response_data['error'])
    
    def test_weak_password_short(self):
        """Test registration with password that's too short."""
        data = {
            "email": "test@example.com",
            "password": "Tet1!"
        }
        response = self.client.post(
            self.registration_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Password must be at least 6 characters long', response_data['error'])
    
    def test_weak_password_no_uppercase(self):
        """Test registration with password missing uppercase character."""
        data = {
            "email": "test@example.com",
            "password": "testpass123!"
        }
        response = self.client.post(
            self.registration_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Password must contain at least 1 uppercase character', response_data['error'])
    
    def test_weak_password_no_special_character(self):
        """Test registration with password missing special character."""
        data = {
            "email": "test@example.com",
            "password": "TestPass123"
        }
        response = self.client.post(
            self.registration_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Password must contain at least 1 special character', response_data['error'])
    
    def test_weak_password_no_numeric(self):
        """Test registration with password missing numeric character."""
        data = {
            "email": "test@example.com",
            "password": "TestPass!"
        }
        response = self.client.post(
            self.registration_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Password must contain at least 1 numeric character', response_data['error'])
    
    @patch('firebase_admin.auth.create_user')
    def test_strong_password_examples(self, mock_create_user):
        """Test various strong password examples."""
        # Mock Firebase user creation
        mock_firebase_user = MagicMock()
        mock_firebase_user.uid = "test_firebase_uid_123"
        mock_create_user.return_value = mock_firebase_user
        
        strong_passwords = [
            "TestPass123!",
            "MyP@ssw0rd",
            "Secure1!",
            "Complex#123",
            "StrongP@ss1"
        ]
        
        for password in strong_passwords:
            with self.subTest(password=password):
                data = {
                    "email": f"test_{password}@example.com",
                    "password": password
                }
                response = self.client.post(
                    self.registration_url,
                    data=json.dumps(data),
                    content_type='application/json'
                )
                
                # Should not fail due to password strength
                self.assertNotEqual(response.status_code, 400)
                response_data = json.loads(response.content)
                if response.status_code == 400:
                    self.assertNotIn('Password must contain', response_data['error'])
    
    @patch('firebase_admin.auth.create_user')
    def test_duplicate_registration(self, mock_create_user):
        """Test registering the same user twice."""
        # Mock Firebase user creation
        mock_firebase_user = MagicMock()
        mock_firebase_user.uid = "test_firebase_uid_123"
        mock_create_user.return_value = mock_firebase_user
        
        # First registration should succeed
        response1 = self.client.post(
            self.registration_url,
            data=json.dumps(self.test_user_data),
            content_type='application/json'
        )
        
        self.assertEqual(response1.status_code, 200)
        
        # Second registration should fail
        response2 = self.client.post(
            self.registration_url,
            data=json.dumps(self.test_user_data),
            content_type='application/json'
        )
        
        self.assertEqual(response2.status_code, 409)
        response_data = json.loads(response2.content)
        self.assertFalse(response_data['success'])
        self.assertIn('User with this email already exists', response_data['error'])
    
    @patch('firebase_admin.auth.create_user')
    def test_firebase_email_already_exists(self, mock_create_user):
        """Test when Firebase returns EmailAlreadyExistsError."""
        from firebase_admin import auth
        
        # Mock Firebase to raise EmailAlreadyExistsError
        mock_create_user.side_effect = auth.EmailAlreadyExistsError("User already exists", None, None)
        
        response = self.client.post(
            self.registration_url,
            data=json.dumps(self.test_user_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 409)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('User with this email already exists in Firebase', response_data['error'])
    
    @patch('firebase_admin.auth.create_user')
    def test_registration_with_minimal_data(self, mock_create_user):
        """Test registration with only required fields."""
        # Mock Firebase user creation
        mock_firebase_user = MagicMock()
        mock_firebase_user.uid = "test_firebase_uid_123"
        mock_create_user.return_value = mock_firebase_user
        
        minimal_data = {
            "email": "minimal@example.com",
            "password": "TestPass123!"
        }
        
        response = self.client.post(
            self.registration_url,
            data=json.dumps(minimal_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertTrue(response_data['success'])
        
        # Check that user was created with default username
        django_user = FirebaseUser.objects.get(email=minimal_data['email'])
        self.assertEqual(django_user.username, "minimal")  # email.split('@')[0]
        self.assertEqual(django_user.first_name, "")
        self.assertEqual(django_user.last_name, "")
    
    def test_invalid_json(self):
        """Test registration with invalid JSON."""
        response = self.client.post(
            self.registration_url,
            data="invalid json",
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 500)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Registration failed', response_data['error'])
    
    def test_wrong_content_type(self):
        """Test registration with wrong content type."""
        response = self.client.post(
            self.registration_url,
            data=json.dumps(self.test_user_data),
            content_type='text/plain'
        )
        
        # Django should still process this, but it's good to test
        self.assertNotEqual(response.status_code, 200)


class EmailVerificationTestCase(TestCase):
    """Test cases for email verification endpoints."""
    
    def setUp(self):
        """Set up test client and base data."""
        self.client = Client()
        self.check_verification_url = reverse('check_email_verification')
        self.resend_email_url = reverse('resend_verification_email')
        self.test_firebase_uid = "test_firebase_uid_123"
        self.test_email = "test@example.com"
    
    @patch('firebase_admin.auth.get_user')
    def test_check_email_verification_success(self, mock_get_user):
        """Test successful email verification check."""
        # Mock Firebase user
        mock_firebase_user = MagicMock()
        mock_firebase_user.email_verified = False
        mock_firebase_user.email = self.test_email
        mock_get_user.return_value = mock_firebase_user
        
        data = {"firebase_uid": self.test_firebase_uid}
        response = self.client.post(
            self.check_verification_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertTrue(response_data['success'])
        self.assertFalse(response_data['email_verified'])
        self.assertEqual(response_data['email'], self.test_email)
    
    @patch('firebase_admin.auth.get_user')
    def test_check_email_verification_verified(self, mock_get_user):
        """Test email verification check for verified user."""
        # Mock Firebase user as verified
        mock_firebase_user = MagicMock()
        mock_firebase_user.email_verified = True
        mock_firebase_user.email = self.test_email
        mock_get_user.return_value = mock_firebase_user
        
        data = {"firebase_uid": self.test_firebase_uid}
        response = self.client.post(
            self.check_verification_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertTrue(response_data['success'])
        self.assertTrue(response_data['email_verified'])
    
    def test_check_email_verification_missing_uid(self):
        """Test email verification check with missing Firebase UID."""
        data = {}
        response = self.client.post(
            self.check_verification_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('No Firebase UID provided', response_data['error'])
    
    @patch('firebase_admin.auth.get_user')
    def test_check_email_verification_user_not_found(self, mock_get_user):
        """Test email verification check for non-existent user."""
        from firebase_admin import auth
        
        # Mock Firebase to raise UserNotFoundError
        mock_get_user.side_effect = auth.UserNotFoundError("User not found", None)
        
        data = {"firebase_uid": "non_existent_uid"}
        response = self.client.post(
            self.check_verification_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 404)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('User not found', response_data['error'])
    
    @patch('firebase_admin.auth.generate_email_verification_link')
    def test_resend_verification_email_success(self, mock_generate_link):
        """Test successful resend of verification email."""
        # Mock Firebase email generation
        mock_generate_link.return_value = "https://example.com/verify?token=123"
        
        data = {"email": self.test_email}
        response = self.client.post(
            self.resend_email_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertTrue(response_data['success'])
        self.assertIn('Verification email sent', response_data['message'])
        self.assertIn('verification_link', response_data)
    
    def test_resend_verification_email_missing_email(self):
        """Test resend verification email with missing email."""
        data = {}
        response = self.client.post(
            self.resend_email_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('No email provided', response_data['error'])
    
    @patch('firebase_admin.auth.generate_email_verification_link')
    def test_resend_verification_email_user_not_found(self, mock_generate_link):
        """Test resend verification email for non-existent user."""
        from firebase_admin import auth
        
        # Mock Firebase to raise UserNotFoundError
        mock_generate_link.side_effect = auth.UserNotFoundError("User not found", None)
        
        data = {"email": "nonexistent@example.com"}
        response = self.client.post(
            self.resend_email_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 404)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('User not found', response_data['error'])
    
    def test_invalid_json_check_verification(self):
        """Test check email verification with invalid JSON."""
        response = self.client.post(
            self.check_verification_url,
            data="invalid json",
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 500)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Error checking email verification', response_data['error'])
    
    def test_invalid_json_resend_email(self):
        """Test resend verification email with invalid JSON."""
        response = self.client.post(
            self.resend_email_url,
            data="invalid json",
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 500)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Error sending verification email', response_data['error'])


class ForgotPasswordTestCase(TestCase):
    """Test cases for the forgot password endpoint."""
    
    def setUp(self):
        """Set up test client and base data."""
        self.client = Client()
        self.forgot_password_url = reverse('forgot_password')
        self.test_email = "test@example.com"
    
    @patch('firebase_admin.auth.get_user_by_email')
    @patch('firebase_admin.auth.generate_password_reset_link')
    def test_successful_password_reset(self, mock_generate_link, mock_get_user):
        """Test successful password reset request."""
        # Mock Firebase user
        mock_user = MagicMock()
        mock_get_user.return_value = mock_user
        mock_generate_link.return_value = "https://example.com/reset"
        
        response = self.client.post(
            self.forgot_password_url,
            data=json.dumps({'email': self.test_email}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertTrue(response_data['success'])
        self.assertEqual(response_data['message'], 'Password reset email sent successfully')
        
        # Verify Firebase was called correctly
        mock_get_user.assert_called_once_with(self.test_email)
        mock_generate_link.assert_called_once_with(self.test_email)
    
    @patch('firebase_admin.auth.get_user_by_email')
    def test_user_not_found(self, mock_get_user):
        """Test password reset when user doesn't exist."""
        # Mock Firebase to raise UserNotFoundError
        from firebase_admin import auth
        mock_get_user.side_effect = auth.UserNotFoundError("User not found", None, None)
        
        response = self.client.post(
            self.forgot_password_url,
            data=json.dumps({'email': 'nonexistent@example.com'}),
            content_type='application/json'
        )
        
        # Should still return success for security (don't reveal if user exists)
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertTrue(response_data['success'])
        self.assertIn('If an account with this email exists', response_data['message'])
    
    def test_missing_email(self):
        """Test password reset with missing email."""
        response = self.client.post(
            self.forgot_password_url,
            data=json.dumps({}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Email is required', response_data['error'])
    
    def test_invalid_email_format(self):
        """Test password reset with invalid email format."""
        response = self.client.post(
            self.forgot_password_url,
            data=json.dumps({'email': 'invalid-email'}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Invalid email format', response_data['error'])
    
    @patch('firebase_admin.auth.get_user_by_email')
    def test_firebase_error(self, mock_get_user):
        """Test password reset when Firebase throws an error."""
        mock_get_user.side_effect = Exception("Firebase error")
        
        response = self.client.post(
            self.forgot_password_url,
            data=json.dumps({'email': self.test_email}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 500)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Failed to send password reset email', response_data['error'])
    
    def test_invalid_json(self):
        """Test password reset with invalid JSON."""
        response = self.client.post(
            self.forgot_password_url,
            data="invalid json",
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Invalid JSON data', response_data['error'])
    
    def test_empty_email(self):
        """Test password reset with empty email."""
        response = self.client.post(
            self.forgot_password_url,
            data=json.dumps({'email': ''}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Email is required', response_data['error'])
    
    def test_whitespace_email(self):
        """Test password reset with whitespace-only email."""
        response = self.client.post(
            self.forgot_password_url,
            data=json.dumps({'email': '   '}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Email is required', response_data['error'])


class UserProfileTestCase(TestCase):
    """Test cases for user profile endpoints."""
    
    def setUp(self):
        """Set up test client and base data."""
        self.client = Client()
        self.profile_url = reverse('user_profile')
        self.test_firebase_uid = "test_firebase_uid_123"
        self.test_email = "test@example.com"
        
        # Create a test user
        self.test_user = FirebaseUser.objects.create(
            firebase_uid=self.test_firebase_uid,
            email=self.test_email,
            username="testuser",
            first_name="Test",
            last_name="User",
            phone_number="+1234567890",
            profile_picture_url="https://example.com/avatar.jpg",
            role="user"
        )
    
    def test_get_user_profile_success(self):
        """Test successful user profile retrieval."""
        response = self.client.get(
            f"{self.profile_url}?firebase_uid={self.test_firebase_uid}"
        )
        
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertTrue(response_data['success'])
        self.assertIn('user', response_data)
        
        user_data = response_data['user']
        self.assertEqual(user_data['email'], self.test_email)
        self.assertEqual(user_data['username'], "testuser")
        self.assertEqual(user_data['first_name'], "Test")
        self.assertEqual(user_data['last_name'], "User")
        self.assertEqual(user_data['phone_number'], "+1234567890")
        self.assertEqual(user_data['profile_picture_url'], "https://example.com/avatar.jpg")
        self.assertEqual(user_data['role'], "user")
        self.assertFalse(user_data['is_admin'])
    
    def test_get_user_profile_missing_uid(self):
        """Test user profile retrieval with missing Firebase UID."""
        response = self.client.get(self.profile_url)
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Firebase UID is required', response_data['error'])
    
    def test_get_user_profile_user_not_found(self):
        """Test user profile retrieval for non-existent user."""
        response = self.client.get(
            f"{self.profile_url}?firebase_uid=nonexistent_uid"
        )
        
        self.assertEqual(response.status_code, 404)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('User not found', response_data['error'])
    
    def test_put_user_profile_success(self):
        """Test successful user profile update."""
        update_data = {
            "firebase_uid": self.test_firebase_uid,
            "username": "newusername",
            "first_name": "NewFirst",
            "last_name": "NewLast",
            "phone_number": "+1987654321"
        }
        
        response = self.client.put(
            self.profile_url,
            data=json.dumps(update_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertTrue(response_data['success'])
        self.assertIn('Profile updated successfully', response_data['message'])
        
        # Verify user was updated in database
        updated_user = FirebaseUser.objects.get(firebase_uid=self.test_firebase_uid)
        self.assertEqual(updated_user.username, "newusername")
        self.assertEqual(updated_user.first_name, "NewFirst")
        self.assertEqual(updated_user.last_name, "NewLast")
        self.assertEqual(updated_user.phone_number, "+1987654321")
    
    def test_put_user_profile_missing_uid(self):
        """Test user profile update with missing Firebase UID."""
        update_data = {
            "username": "newusername"
        }
        
        response = self.client.put(
            self.profile_url,
            data=json.dumps(update_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Firebase UID is required', response_data['error'])
    
    def test_put_user_profile_user_not_found(self):
        """Test user profile update for non-existent user."""
        update_data = {
            "firebase_uid": "nonexistent_uid",
            "username": "newusername"
        }
        
        response = self.client.put(
            self.profile_url,
            data=json.dumps(update_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 404)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('User not found', response_data['error'])
    
    def test_put_user_profile_username_conflict(self):
        """Test user profile update with username that's already taken."""
        # Create another user with different username
        other_user = FirebaseUser.objects.create(
            firebase_uid="other_uid_456",
            email="other@example.com",
            username="takenusername"
        )
        
        update_data = {
            "firebase_uid": self.test_firebase_uid,
            "username": "takenusername"  # This username is already taken
        }
        
        response = self.client.put(
            self.profile_url,
            data=json.dumps(update_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 409)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Username is already taken', response_data['error'])
    
    def test_put_user_profile_role_update(self):
        """Test user profile update with role change."""
        update_data = {
            "firebase_uid": self.test_firebase_uid,
            "role": "admin"
        }
        
        response = self.client.put(
            self.profile_url,
            data=json.dumps(update_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        
        # Verify role was updated
        updated_user = FirebaseUser.objects.get(firebase_uid=self.test_firebase_uid)
        self.assertEqual(updated_user.role, "admin")
        self.assertTrue(updated_user.is_admin)
    
    def test_put_user_profile_invalid_role(self):
        """Test user profile update with invalid role."""
        update_data = {
            "firebase_uid": self.test_firebase_uid,
            "role": "invalid_role"
        }
        
        response = self.client.put(
            self.profile_url,
            data=json.dumps(update_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)  # Invalid role is ignored
        
        # Verify role was not changed
        updated_user = FirebaseUser.objects.get(firebase_uid=self.test_firebase_uid)
        self.assertEqual(updated_user.role, "user")  # Should remain unchanged
    
    def test_put_user_profile_invalid_json(self):
        """Test user profile update with invalid JSON."""
        response = self.client.put(
            self.profile_url,
            data="invalid json",
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Invalid JSON data', response_data['error'])
    
    def test_user_profile_method_not_allowed(self):
        """Test that other HTTP methods are not allowed."""
        # Test POST method
        response = self.client.post(self.profile_url)
        self.assertEqual(response.status_code, 405)
        
        # Test DELETE method
        response = self.client.delete(self.profile_url)
        self.assertEqual(response.status_code, 405)


class DeleteAccountTestCase(TestCase):
    """Test cases for the delete account endpoint."""
    
    def setUp(self):
        """Set up test client and base data."""
        self.client = Client()
        self.delete_url = reverse('delete_account')
        self.test_firebase_uid = "test_firebase_uid_123"
        
        # Create a test user in Django database
        self.test_user = FirebaseUser.objects.create(
            firebase_uid=self.test_firebase_uid,
            email="test@example.com",
            username="testuser",
            first_name="Test",
            last_name="User",
            role="user"
        )
    
    @patch('firebase_admin.auth.delete_user')
    def test_successful_account_deletion(self, mock_delete_user):
        """Test successful account deletion."""
        # Mock Firebase user deletion
        mock_delete_user.return_value = None
        
        # Make delete request (now using POST)
        delete_data = {"firebase_uid": self.test_firebase_uid}
        response = self.client.post(
            self.delete_url,
            data=json.dumps(delete_data),
            content_type='application/json'
        )
        
        # Check response
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertTrue(response_data['success'])
        self.assertIn('deleted successfully', response_data['message'])
        
        # Check that user was deleted from Django database
        self.assertFalse(FirebaseUser.objects.filter(firebase_uid=self.test_firebase_uid).exists())
        
        # Verify Firebase was called correctly
        mock_delete_user.assert_called_once_with(self.test_firebase_uid)
    
    def test_delete_account_missing_firebase_uid(self):
        """Test account deletion with missing Firebase UID."""
        delete_data = {}
        response = self.client.post(
            self.delete_url,
            data=json.dumps(delete_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Firebase UID is required', response_data['error'])
    
    def test_delete_account_user_not_found(self):
        """Test account deletion for non-existent user."""
        delete_data = {"firebase_uid": "non_existent_uid"}
        response = self.client.post(
            self.delete_url,
            data=json.dumps(delete_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 404)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('User not found', response_data['error'])
    
    @patch('firebase_admin.auth.delete_user')
    def test_delete_account_firebase_error(self, mock_delete_user):
        """Test account deletion when Firebase deletion fails."""
        # Mock Firebase deletion to raise an exception
        mock_delete_user.side_effect = Exception("Firebase error")
        
        delete_data = {"firebase_uid": self.test_firebase_uid}
        response = self.client.post(
            self.delete_url,
            data=json.dumps(delete_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 500)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Failed to delete Firebase account', response_data['error'])
        
        # Check that user still exists in Django database
        self.assertTrue(FirebaseUser.objects.filter(firebase_uid=self.test_firebase_uid).exists())
    
    def test_delete_account_invalid_json(self):
        """Test account deletion with invalid JSON."""
        response = self.client.post(
            self.delete_url,
            data="invalid json",
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Invalid JSON data', response_data['error'])
    
    def test_delete_account_method_not_allowed(self):
        """Test that other HTTP methods are not allowed."""
        # Test GET method
        response = self.client.get(self.delete_url)
        self.assertEqual(response.status_code, 405)
        
        # Test PUT method
        response = self.client.put(self.delete_url)
        self.assertEqual(response.status_code, 405)
        
        # Test DELETE method
        response = self.client.delete(self.delete_url)
        self.assertEqual(response.status_code, 405)
    
    def test_delete_account_empty_firebase_uid(self):
        """Test account deletion with empty Firebase UID."""
        delete_data = {"firebase_uid": ""}
        response = self.client.post(
            self.delete_url,
            data=json.dumps(delete_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Firebase UID is required', response_data['error'])
    
    @patch('firebase_admin.auth.delete_user')
    def test_delete_account_preserves_other_users(self, mock_delete_user):
        """Test that deleting one account doesn't affect other users."""
        # Create another user
        other_user = FirebaseUser.objects.create(
            firebase_uid="other_uid_456",
            email="other@example.com",
            username="otheruser"
        )
        
        # Mock Firebase user deletion
        mock_delete_user.return_value = None
        
        # Delete the first user
        delete_data = {"firebase_uid": self.test_firebase_uid}
        response = self.client.post(
            self.delete_url,
            data=json.dumps(delete_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        
        # Check that only the first user was deleted
        self.assertFalse(FirebaseUser.objects.filter(firebase_uid=self.test_firebase_uid).exists())
        self.assertTrue(FirebaseUser.objects.filter(firebase_uid="other_uid_456").exists())
        
        # Verify Firebase was called only once for the correct user
        mock_delete_user.assert_called_once_with(self.test_firebase_uid)
