from django.http import response
from .test_setup import TestSetup
from ..models import User


class TestView(TestSetup):
    
    def test_user_cannot_register_with_no_data(self):
        res = self.client.post(self.register_url)
        self.assertEqual(res.status_code, 400)
        
    def test_user_can_register(self):
        res = self.client.post(self.register_url, self.user_data, format='json')
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.data['email'], self.user_data['email'])
        self.assertEqual(res.data['username'], self.user_data['username'])
        
    def test_user_verified_login(self):
        response = self.client.post(self.register_url, self.user_data, format='json')
        self.client.post(self.register_url, self.user_data, format='json')
        email = response.data['email']
        user = User.object.get(email=email)
        user.is_verified = True
        user.save()
        res = self.client.post(self.login_url, self.user_data, format='json')
        self.assertEqual(res.status_code, 200)