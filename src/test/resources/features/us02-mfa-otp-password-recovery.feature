@US02 @EP01 @erp-auth-service
# User Story: US02 - Configure multi-factor verification (2FA/OTP) and recover credentials
Feature: Multi-Factor Authentication (2FA/OTP) and Password Recovery
  As a registered user
  I want to enroll TOTP two-factor authentication, verify email OTP codes, and reset forgotten passwords
  So that my account is protected against unauthorized access and credential compromise

  Background:
    Given the "erp-auth-service" REST API is available at "/api/v1"

  @US02 @happy-path
  # User Story: US02 - Initiate and confirm TOTP second factor enrollment
  Scenario: Authenticated user enrolls and confirms TOTP second factor
    Given an authenticated user with a valid JWT bearer token for "mechanic@driveos.pe"
    When the client sends a "POST" request to "/api/v1/users/me/second-factor"
    Then the response status code should be 200
    And the JSON response should contain "secret" and "qrCodeUri"
    When the client sends a "POST" request to "/api/v1/users/me/second-factor/confirm" with JSON payload:
      """
      {
        "code": "123456"
      }
      """
    Then the response status code should be 200
    And the JSON response field "enabled" should be true

  @US02 @happy-path
  # User Story: US02 - Request password recovery and reset password with valid token
  Scenario: Registered user completes password recovery flow with a valid reset token
    Given a registered user with email "owner@driveos.pe"
    When the client sends a "POST" request to "/api/v1/auth/forgot-password" with JSON payload:
      """
      {
        "email": "owner@driveos.pe"
      }
      """
    Then the response status code should be 200
    When the client sends a "POST" request to "/api/v1/auth/reset-password" with a valid issued token and new password "NewStrongPass!2026"
    Then the response status code should be 200

  @US02 @negative
  # User Story: US02 - Reject expired or invalid OTP verification code
  Scenario: Verifying an invalid or expired OTP code returns HTTP 400
    Given an OTP verification challenge was sent to "owner@driveos.pe"
    When the client sends a "POST" request to "/api/v1/authentication/otp/verify" with JSON payload:
      """
      {
        "email": "owner@driveos.pe",
        "code": "000000"
      }
      """
    Then the response status code should be 400
    And the JSON response should contain an error message indicating invalid or expired OTP code
