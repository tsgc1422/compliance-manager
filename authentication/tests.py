from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()

class AuthenticationTests(APITestCase):

    def setUp(self):
        """Set up test users and tokens before each test."""
        self.client = APIClient()

        # Create test users
        self.user = User.objects.create_user(username="user1", email="user1@test.com", password="Test@1234", role="engineer")
        self.admin = User.objects.create_superuser(username="admin", email="admin@test.com", password="Admin@1234", role="admin")

        # Generate tokens for authentication
        self.user_token = str(RefreshToken.for_user(self.user).access_token)
        self.admin_token = str(RefreshToken.for_user(self.admin).access_token)

    # ✅ Test Successful User Registration
    def test_user_registration_success(self):
        data = {"username": "newuser", "email": "newuser@test.com", "password": "Test@1234", "role": "engineer"}
        response = self.client.post("/users/", data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["username"], "newuser")

    # ❌ Test Registration with Missing Fields
    def test_user_registration_missing_fields(self):
        data = {"username": "", "email": "missing@test.com", "password": "Test@1234"}
        response = self.client.post("/users/", data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # ❌ Test Registration with Existing Username
    def test_user_registration_existing_username(self):
        data = {"username": "user1", "email": "duplicate@test.com", "password": "Test@1234", "role": "engineer"}
        response = self.client.post("/users/", data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # ❌ Test Registration with Weak Password
    def test_user_registration_weak_password(self):
        data = {"username": "weakpass", "email": "weakpass@test.com", "password": "123"}
        response = self.client.post("/users/", data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # ✅ Test Successful User Login
    def test_user_login_success(self):
        data = {"username": "user1", "password": "Test@1234"}
        response = self.client.post("/auth/login/", data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)

    # ❌ Test Login with Incorrect Password
    def test_user_login_incorrect_password(self):
        data = {"username": "user1", "password": "WrongPass123"}
        response = self.client.post("/auth/login/", data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # ❌ Test Login with Non-Existent User
    def test_user_login_non_existent_user(self):
        data = {"username": "nonexistent", "password": "DoesntExist123"}
        response = self.client.post("/auth/login/", data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # ✅ Test Successful Token Refresh
    def test_token_refresh_success(self):
        refresh = str(RefreshToken.for_user(self.user))
        response = self.client.post("/auth/token/refresh/", {"refresh": refresh})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)

    # ❌ Test Token Refresh with Invalid Token
    def test_token_refresh_invalid_token(self):
        response = self.client.post("/auth/token/refresh/", {"refresh": "invalid_refresh_token"})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # ✅ Test Accessing Profile of Logged-in User
    def test_get_user_profile_success(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.user_token}")
        response = self.client.get("/users/me/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["username"], "user1")

    # ❌ Test Accessing Profile Without Authentication
    def test_get_user_profile_unauthenticated(self):
        response = self.client.get("/users/me/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # ✅ Test Admin Can List All Users
    def test_admin_can_list_users(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_token}")
        response = self.client.get("/users/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(len(response.data) > 0)

    # ❌ Test Regular User Cannot List Users
    def test_regular_user_cannot_list_users(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.user_token}")
        response = self.client.get("/users/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # ✅ Test User Can Update Their Own Profile
    def test_user_can_update_own_profile(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.user_token}")
        data = {"email": "updateduser@test.com"}
        response = self.client.patch(f"/users/{self.user.id}/", data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], "updateduser@test.com")

    # ❌ Test User Cannot Update Another User's Profile
    def test_user_cannot_update_other_user_profile(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.user_token}")
        data = {"email": "hackedemail@test.com"}
        response = self.client.patch(f"/users/{self.admin.id}/", data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # ✅ Test Admin Can Delete Users
    def test_admin_can_delete_user(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_token}")
        response = self.client.delete(f"/users/{self.user.id}/")
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    # ❌ Test Regular User Cannot Delete Another User
    def test_user_cannot_delete_other_user(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.user_token}")
        response = self.client.delete(f"/users/{self.admin.id}/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)