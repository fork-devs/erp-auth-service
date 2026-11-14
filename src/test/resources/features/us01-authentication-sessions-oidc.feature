@US01 @EP01 @erp-auth-service
# User Story: US01 - Manage authentication sessions and federated OIDC identity
Feature: Authentication Sessions and Federated OIDC Identity
  As a platform user (workshop admin, service advisor, or mechanic)
  I want to sign in, refresh, and revoke sessions using local credentials or Google OIDC
  So that I can securely access authorized workshop resources across the platform

  Background:
    Given the "erp-auth-service" REST API is available at "/api/v1"
    And the OIDC discovery and JWKS endpoints are publicly exposed

  @US01 @happy-path
  # User Story: US01 - Authenticate user with valid local credentials
  Scenario: Successful login with valid credentials returns RS256 access and refresh tokens
    Given a registered active user with email "advisor@driveos.pe" and valid password "SecurePass!2026" in tenant "tenant-lima-01"
    When the client sends a "POST" request to "/api/v1/auth/login" with JSON payload:
      """
      {
        "email": "advisor@driveos.pe",
        "password": "SecurePass!2026"
      }
      """
    Then the response status code should be 200
    And the JSON response should contain non-empty fields "accessToken" and "refreshToken"
    And the decoded JWT "accessToken" should include claims "tenant_id" and "roles"
    And a "GET" request to "/.well-known/jwks.json" should return status 200 with at least 1 RSA key

  @US01 @happy-path
  # User Story: US01 - Renew access token using active refresh token
  Scenario: Refreshing an active session issues a new access token without re-entering password
    Given an authenticated user with an active refresh token "valid-refresh-token-uuid"
    When the client sends a "POST" request to "/api/v1/auth/refresh" with JSON payload:
      """
      {
        "refreshToken": "valid-refresh-token-uuid"
      }
      """
    Then the response status code should be 200
    And the JSON response should contain a newly issued "accessToken"

  @US01 @negative
  # User Story: US01 - Reject login with invalid password
  Scenario: Login fails with HTTP 401 when credentials are invalid
    Given a registered active user with email "advisor@driveos.pe"
    When the client sends a "POST" request to "/api/v1/auth/login" with JSON payload:
      """
      {
        "email": "advisor@driveos.pe",
        "password": "WrongPassword!999"
      }
      """
    Then the response status code should be 401
    And the JSON response should contain an error message indicating invalid credentials

  @US01 @negative
  # User Story: US01 - Reject session refresh after logout revocation
  Scenario: Refreshing a revoked session token fails with HTTP 401
    Given a user session whose refresh token "revoked-refresh-token" was revoked via "POST /api/v1/auth/logout"
    When the client sends a "POST" request to "/api/v1/auth/refresh" with JSON payload:
      """
      {
        "refreshToken": "revoked-refresh-token"
      }
      """
    Then the response status code should be 401
    And the JSON response should contain an error message indicating the token is revoked or invalid
