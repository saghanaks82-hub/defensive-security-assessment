# EdVyro Internship — Project 5
## Defensive Security Assessment Capstone

### Project Overview

This project focuses on assessing the security of a locally hosted Flask authentication application. The objective is to identify potential security weaknesses, review existing defensive controls, implement appropriate improvements, and document the results of security testing.

### Objectives

- Assess authentication and registration security.
- Review password hashing and input validation.
- Evaluate login rate limiting and CSRF protection.
- Review session management and cookie security.
- Audit Python dependencies for known vulnerabilities.
- Implement and assess security event logging.
- Document findings, remediation steps, and test results.

### Scope and Authorization

All testing is limited to my own application running locally on my computer.

- **Target:** Local Flask authentication application.
- **Environment:** Local development environment (`127.0.0.1`).
- **Testing approach:** Defensive security assessment and manual verification.
- **Out of scope:** External websites, third-party systems, production services, and real user data.

See [SCOPE.md](SCOPE.md) for the full scope and rules of engagement.

### Technologies Used

- Python
- Flask
- SQLite
- Flask-Limiter
- Werkzeug password hashing
- HTML
- Python dependency auditing tools

### Security Controls Assessed

- Password hashing
- Authentication and input validation
- Login rate limiting
- CSRF protection
- Session and cookie configuration
- Logout and protected dashboard access
- Dependency vulnerability auditing
- Security event logging

### Testing Summary

The assessment included registration and login tests, invalid-input checks, failed-login handling, rate-limit testing, logout verification, cookie configuration review, and dependency auditing.

The dependency audit reported no known vulnerabilities at the time of testing. Security logging was added to record security-related events. See the assessment report for test results, limitations, and verification details.

### Security Improvements

- Added security-event logging.
- Reviewed authentication and session protections.
- Maintained password hashing and parameterized database queries.
- Reviewed rate limiting and CSRF protection.
- Audited dependencies for known vulnerabilities.

### Project Files

- `app.py` — Flask authentication application.
- `SCOPE.md` — Assessment scope and authorization.
- `SECURITY-ASSESSMENT-REPORT.md` — Findings, test results, and recommendations.
- `.gitignore` — Excludes files that should not be committed.

### Limitations

This assessment was performed in a local development environment. It does not establish that the application is production-ready. Production deployment configuration, log rotation, centralized monitoring, and
