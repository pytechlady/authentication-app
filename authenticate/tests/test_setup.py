from rest_framework.test import APITestCase
from django.urls import reverse
from faker import Faker


class TestSetup(APITestCase):
    
    def setUp(self):   
        self.register_url=reverse('register')
        self.login_url=reverse('login')
        self.faker = Faker()
        
        self.user_data={
            'email': self.faker.email(),
            'username': self.faker.email().split('@')[0],
            'password': self.faker.email(),
        }
        
        return super().setUp()
    
    def tearDown(self):
        return super().tearDown()
    