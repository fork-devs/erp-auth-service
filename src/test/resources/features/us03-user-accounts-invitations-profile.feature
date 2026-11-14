@US03 @EP01 @erp-auth-service
# User Story: US03 - Manage user accounts, invitations, and own profile lifecycle
Feature: User Accounts, Invitations, and Profile Lifecycle
  As a workshop administrator or authenticated user
  I want to create users, send employee invitations, list accounts, and update my own email or password
  So that organization identities and access permissions remain accurate and controlled

  Background:
    Given the "erp-auth-service" REST API is available at "/api/v1"

  @US03 @happy-path
  # User Story: US03 - Workshop admin creates a new user account
  Scenario: Workshop administrator creates a new user within their tenant
    Given an authenticated user with role "WORKSHOP_ADMIN" in tenant "tenant-lima-01"
    When the client sends a "POST" request to "/api/v1/users" with JSON payload:
      """
      {
        "email": "new.tech@driveos.pe",
        "password": "InitPass!2026",
        "fullName": "Carlos Mendoza",
        "role": "TECHNICIAN"
      }
      """
    Then the response status code should be 201
    And the JSON response should contain a generated "id"
    And the JSON response field "email" should equal "new.tech@driveos.pe"

  @US03 @happy-path
  # User Story: US03 - Authenticated user queries own profile
  Scenario: Authenticated user retrieves their active profile via /users/me
    Given an authenticated user "advisor@driveos.pe" with role "SERVICE_ADVISOR"
    When the client sends a "GET" request to "/api/v1/users/me"
    Then the response status code should be 200
    And the JSON response field "email" should equal "advisor@driveos.pe"
    And the JSON response should include "roles" and "tenantId"

  @US03 @negative
  # User Story: US03 - Prevent duplicate email on user creation or email update
  Scenario: Creating a user with an already registered email returns HTTP 409 Conflict
    Given an authenticated user with role "WORKSHOP_ADMIN"
    And a user with email "existing.user@driveos.pe" already exists in the system
    When the client sends a "POST" request to "/api/v1/users" with JSON payload:
      """
      {
        "email": "existing.user@driveos.pe",
        "password": "InitPass!2026",
        "fullName": "Duplicate User",
        "role": "TECHNICIAN"
      }
      """
    Then the response status code should be 409
    And the JSON response should contain an error message indicating email already exists

  @US03 @negative
  # User Story: US03 - Reject password change when current password is incorrect
  Scenario: Updating password with an incorrect current password returns HTTP 400
    Given an authenticated user with id "user-uuid-001"
    When the client sends a "PUT" request to "/api/v1/users/user-uuid-001/password" with JSON payload:
      """
      {
        "currentPassword": "WrongCurrentPassword!",
        "newPassword": "NewValidPassword!2026"
      }
      """
    Then the response status code should be 400
    And the JSON response should contain an error message indicating the current password is invalid
