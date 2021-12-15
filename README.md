## Building Restful API with Django & DRF

## The Authentication System

### Overview

* This is a django rest-framework API projects that includes Register, OTP for user verification, OTP confirmation, Login, Login, Forgot password and also reset password end points. With this project users has to register with a valid email address as an OTP will be sent to the email to verify user. User would not be verified or be able to login if OTP is not confirmed

### Expectations

1. Register - User should be able to login using a valid and unique email address(email address that does not already exist in the database), a username and password.

2. Generate OTP - A 6 digits OTP will be sent to the email address provided during registration to verify that the email exist

3. OTP Verification endpoint - The OTP sent will then be used for confirmation, if valid user will then be verified and will be able to Login

4. Login - User should be able able to login with the registered email and password once they receive the OTP and have been verified. A login token will be generated

5. Logout - User should be able to logout out of session. The logout endpoint terminates the user session

6. Forgot password - User should be able to request for password reset. A mail with a token for reset will be sent to the email provided if the email already exist in the database

7. Reset password - User will use the token received to create a new password and then user will be able to login using the email and the new password created.