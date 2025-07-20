from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
import json
from unittest.mock import patch, MagicMock
from .models import FirebaseUser

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
