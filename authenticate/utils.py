from django.core.mail import EmailMessage
import random

class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage(subject=data['email_subject'], body=data['email_body'], to=[data['to_email']])
        email.send()
        
    @staticmethod
    def generate_otp(number):
        min_val = 10 ** (number -1)
        max_val = (10** number) -1
        otp = random.randint(min_val, max_val)
        return otp