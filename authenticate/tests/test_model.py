from django.http import response
from .test_setup import TestSetup
from django.urls import reverse
from ..models import User


class TestModel(TestSetup):
    def test_model_list(self):
        response = self.client.get('model_list')
        self.assertNotEqual(response.status_code, 400)
        
    def test_model_detail(self):
        mm_objs = User.object.all()
        if mm_objs:
            response = self.client.get(reverse('model-detail', args=[mm_objs[0].id]))
            self.assertEqual(response.status_code, 200)