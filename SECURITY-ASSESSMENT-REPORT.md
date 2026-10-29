# Defensive Security Assessment Report

## 1. Project Overview
 
**Internship:** EdVyro — Project 5  
**Assessment Type:** Defensive Security Assessment  
**Environment:** Local Flask application on localhost

## 2. Scope and Authorization

Testing was limited to my own local application. No external systems or production services were targeted. Synthetic test accounts were used.

## 3. Security Controls Assessed

- Password hashing
- Login and registration validation
- Authentication failure handling
- Login rate limiting
- CSRF protection
- Session and cookie configuration
- Logout and protected dashboard access
- Dependency vulnerability auditing
- Security event logging

## 4. Test Results

The following security tests were performed during the assessment:

1. **Valid Registration:** Passed
2. **Invalid Username Validation:** Passed
3. **Short Password Rejection:** Passed
4. **Correct Login:** Passed
5. **Incorrect Password Rejection:** Passed
6. **Login Rate Limiting:** Passed
7. **Logout and Dashboard Protection:** Passed
8. **Cookie Security Attributes:** Passed
9. **Password Hashing Review:** Passed
10. **Dependency Vulnerability Audit:** No known vulnerabilities found
11. **Security Logging:** Passed
12. **Session Expiry:** Configured for 15 minutes; actual expiration behavior was not verified.

## 5. Security Improvements

- Added security-event logging.
- Recorded authentication and other security-related events without intentionally logging passwords or CSRF tokens.
- Reviewed authentication, validation, and session protections.
- Audited installed Python dependencies for known vulnerabilities.

## 6. Limitations

The assessment was limited to the local development application. Production deployment security, centralized monitoring, log rotation, and actual session-expiration behavior were not fully assessed.

## 7. Conclusion

The assessment reviewed key defensive controls in the Secure Authentication Lab. The tested authentication and rate-limiting checks passed, and the dependency audit reported no known vulnerabilities. Security logging was tested, with the result reported as passed. Further testing is recommended before any production deployment.