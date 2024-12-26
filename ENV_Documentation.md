# Environment Variables Documentation

This document provides detailed information about the environment variables used in the Beek project. Proper configuration of these variables is essential for the correct functioning of the application. Below are the descriptions, expected values, and usage details for each variable.

---

## Table of Contents

1. [Django Settings](#django-settings)
2. [Database Configuration](#database-configuration)
3. [Password Reset](#password-reset)
4. [Email Configuration](#email-configuration)
5. [Superuser Credentials](#superuser-credentials)
6. [Stripe Integration](#stripe-integration)
7. [1Up Health API Integration](#1up-health-api-integration)
8. [Security Settings](#security-settings)
9. [AWS SQS Configuration](#aws-sqs-configuration)
10. [Celery Configuration](#celery-configuration)
11. [Redis Configuration](#redis-configuration)
12. [AWS S3 Configuration](#aws-s3-configuration)
13. [Notification API](#notification-api)
14. [URLs Configuration](#urls-configuration)
15. [Token Lifetime](#token-lifetime)
16. [Additional Settings](#additional-settings)

---

## Django Settings

### `SECRET_KEY`
- **Description:** A secret key for Django’s cryptographic signing. Keep this value secure.
- **Example:** `django-insecure-d6&)g2y1b&#8nloaza8flr$o&8%kni4^wp(&hz9c4ou^r-9b$f`
- **Required:** Yes

### `DEBUG`
- **Description:** Determines whether Django is running in debug mode. Should be set to `False` in production.
- **Default:** `True`
- **Possible Values:** `True` or `False`
- **Required:** Yes

---

## Database Configuration

### `DB_NAME`
- **Description:** Name of the database.
- **Example:** `mydatabase`
- **Required:** Yes

### `DB_USER`
- **Description:** Database user name.
- **Example:** `dbuser`
- **Required:** Yes

### `DB_PASSWORD`
- **Description:** Password for the database user.
- **Example:** `securepassword`
- **Required:** Yes

### `DB_HOST`
- **Description:** Host address of the database.
- **Example:** `localhost` or `db.example.com`
- **Required:** Yes

### `DB_PORT`
- **Description:** Port number on which the database is listening.
- **Example:** `5432`
- **Default:** Typically depends on the database (e.g., `5432` for PostgreSQL)
- **Required:** Yes

---

## Password Reset

### `PASSWORD_RESET_TOKEN_EXPIRY_DAYS`
- **Description:** Number of days before a password reset token expires.
- **Default:** `1`
- **Required:** Yes

### `PASSWORD_RESET_FE_URL`
- **Description:** Frontend URL to redirect users for password resetting.
- **Example:** `https://frontend.example.com/reset-password`
- **Required:** Yes

---

## Email Configuration

### `EMAIL_BACKEND`
- **Description:** Backend to use for sending emails.
- **Example:** `django.core.mail.backends.smtp.EmailBackend`
- **Required:** Yes

### `EMAIL_HOST`
- **Description:** Hostname of the email server.
- **Example:** `smtp.gmail.com`
- **Required:** Yes

### `EMAIL_PORT`
- **Description:** Port number for the email server.
- **Example:** `587`
- **Required:** Yes

### `EMAIL_USE_TLS`
- **Description:** Whether to use TLS for email.
- **Default:** `True`
- **Possible Values:** `True` or `False`
- **Required:** Yes

### `EMAIL_HOST_USER`
- **Description:** Username for the email server.
- **Example:** `user@example.com`
- **Required:** Yes

### `EMAIL_HOST_PASSWORD`
- **Description:** Password for the email server.
- **Example:** `emailpassword`
- **Required:** Yes

### `DEFAULT_FROM_EMAIL`
- **Description:** Default email address to use for various automated correspondence from the site manager(s).
- **Example:** `noreply@example.com`
- **Required:** Yes

---

## Superuser Credentials

### `SUPERUSER_EMAIL`
- **Description:** Email address for the Django superuser.
- **Example:** `admin@example.com`
- **Required:** Yes

### `SUPERUSER_PASSWORD`
- **Description:** Password for the Django superuser.
- **Example:** `adminpassword`
- **Required:** Yes

---

## Stripe Integration

### `STRIPE_SECRET`
- **Description:** Secret API key for Stripe payment processing.
- **Example:** `sk_test_4eC39HqLyjWDarjtT1zdp7dc`
- **Required:** Yes

### `STRIPE_WEBHOOK`
- **Description:** Secret API key for Stripe webhook validation and processing.
- **Example:** `whsec_4eC39xxxxxxxHqLyjWDarjtT1zdp7dcxxxxxxxxxxxxxxxxx`
- **Required:** Yes

---

## 1Up Health API Integration

### `1UP_CLIENT_ID`
- **Description:** Client ID for 1Up Health API authentication.
- **Example:** `your-client-id`
- **Required:** Yes

### `1UP_CLIENT_SECRET`
- **Description:** Client secret for 1Up Health API authentication.
- **Example:** `your-client-secret`
- **Required:** Yes

### `1UP_BASE_URL`
- **Description:** Base URL for the 1Up Health API.
- **Default:** `https://api.1up.health/`
- **Required:** Yes

### `GENERATE_AUTH_CODE_URL`
- **Description:** URL to generate an authentication code.
- **Default:** `'https://api.1up.health/user-management/v1/user/auth-code'`
- **Required:** Yes

### `GENERATE_ACCESS_TOKEN_URL`
- **Description:** URL to generate an access token.
- **Default:** `'https://auth.1up.health/oauth2/token'`
- **Required:** Yes

### `BULK_DATA_EXPORT_URL`
- **Description:** URL for bulk data export.
- **Default:** `'https://analytics.1up.health/bulk-data/r4/$export?_type=Condition,DocumentReference,Encounter,MedicationRequest'`
- **Required:** Yes

---

## Security Settings

### `CSRF_TRUSTED_ORIGINS`
- **Description:** A list of trusted origins for Cross-Site Request Forgery protection.
- **Example:** `https://yourdomain.com`
- **Required:** Yes

### `CORS_ALLOWED_ORIGINS`
- **Description:** A list of origins that are authorized to make cross-site HTTP requests.
- **Example:** `https://yourfrontend.com`
- **Required:** Yes

### `ALLOWED_HOSTS`
- **Description:** A list of strings representing the host/domain names that this Django site can serve.
- **Example:** `['yourdomain.com', 'www.yourdomain.com']`
- **Required:** Yes

### `ACCESS_TOKEN_LIFETIME_IN_MINUTES`
- **Description:** Lifetime of access tokens in minutes.
- **Default:** `5`
- **Required:** Yes

---

## AWS SQS Configuration

### `AWS_SQS_REGION`
- **Description:** AWS region for SQS.
- **Example:** `us-east-1`
- **Required:** Yes

### `AWS_SQS_ACCESS_KEY_ID`
- **Description:** AWS access key ID for SQS.
- **Required:** Yes

### `AWS_SQS_SECRET_ACCESS_KEY`
- **Description:** AWS secret access key for SQS.
- **Required:** Yes

### `AWS_SQS_GENERAL_URL`
- **Description:** URL for the general SQS queue.
- **Example:** `https://sqs.us-east-1.amazonaws.com/123456789012/`
- **Required:** Yes

### `AWS_SQS_QUEUE`
- **Description:** Name of the primary SQS queue.
- **Example:** `beek-queue-loc`
- **Required:** Yes

### `AWS_SQS_CONDITION_QUEUE`
- **Description:** Name of the condition SQS queue.
- **Example:** `beek-condition-queue-loc`
- **Required:** Yes

### `AWS_SQS_ENCOUNTER_QUEUE`
- **Description:** Name of the encounter SQS queue.
- **Example:** `beek-encounter-queue-loc`
- **Required:** Yes

### `AWS_SQS_MEDICATION_REQUEST_QUEUE`
- **Description:** Name of the medication request SQS queue.
- **Example:** `beek-medication-request-queue-loc`
- **Required:** Yes

### `AWS_SQS_DOCUMENT_REFERENCE_QUEUE`
- **Description:** Name of the document reference SQS queue.
- **Example:** `beek-document-reference-queue-loc`
- **Required:** Yes

---

## Celery Configuration

### `CELERY_RESULT_BACKEND`
- **Description:** Backend used by Celery to store task results.
- **Example:** `redis://localhost:6379/0`
- **Required:** Yes

### `DELAY_TIME_IN_SEC`
- **Description:** Delay time in seconds for initial sync task execution.
- **Default:** `600` (10 minutes)
- **Required:** Yes

---

## Redis Configuration

### `WS_REDIS_HOST`
- **Description:** Hostname for Redis.
- **Example:** `localhost`
- **Required:** Yes

### `WS_REDIS_PORT`
- **Description:** Port number for Redis.
- **Example:** `6379`
- **Required:** Yes

### `WS_REDIS_PASSWORD`
- **Description:** Password for Redis.
- **Example:** `redispassword`
- **Required:** Yes

### `WS_REDIS_SSL`
- **Description:** Whether to use SSL for Redis connections.
- **Default:** `False`
- **Possible Values:** `True` or `False`
- **Required:** Yes

---

## AWS S3 Configuration

### `S3_BUCKET_NAME`
- **Description:** Name of the AWS S3 bucket.
- **Example:** `my-s3-bucket`
- **Required:** Yes

### `S3_ACCESS_KEY`
- **Description:** AWS access key for S3.
- **Required:** Yes

### `S3_SECRET_KEY`
- **Description:** AWS secret key for S3.
- **Required:** Yes

### `S3_BUCKET_FOLDER_PREFIX`
- **Description:** Folder prefix within the S3 bucket.
- **Example:** `dev_loc`
- **Required:** Yes

### `AWS_S3_SIGNATURE_VERSION`
- **Description:** Signature version for AWS S3.
- **Example:** `s3v4`
- **Required:** Yes

---

## Notification API

### `BEEK_NOTIFICATION_API`
- **Description:** Endpoint for the Beek Notification API.
- **Example:** `https://api.yourdomain.com/notifications`
- **Required:** Yes

---

## URLs Configuration

### `BACKEND_URL`
- **Description:** URL for the backend server.
- **Default:** `http://localhost:8000`
- **Required:** Yes

### `FE_URL`
- **Description:** URL for the frontend application.
- **Example:** `https://frontend.yourdomain.com`
- **Required:** Yes

### `EMAIL_RESET_FE_URL`
- **Description:** Frontend URL for password reset.
- **Example:** `https://frontend.example.com/reset-password`
- **Required:** Yes

### `EMAIL_VERIFICATION_FE_URL`
- **Description:** Frontend URL for email verification.
- **Example:** `https://frontend.example.com/verify-email`
- **Required:** Yes

---

## Token Lifetime

### `ACTIVATION_TOKEN_EXPIRY_HOURS`
- **Description:** Number of hours before an activation token expires.
- **Default:** `24`
- **Required:** Yes

---

## Additional Settings

### `FREE_TRIAL_PERIOD_IN_DAYS`
- **Description:** Duration of the free trial period in days.
- **Default:** `7`
- **Required:** Yes

### `AWS_S3_CUSTOM_DOMAIN`
- **Description:** AWS S3 CDN URL.
- **Example:** f7xx5gxxxxn0x.cloudfront.net
- **Required:** No

---

## Summary of Required Variables

Ensure that all required environment variables are set to avoid runtime errors. Below is a checklist of essential variables:

- `SECRET_KEY`
- `DEBUG`
- `DB_NAME`
- `DB_USER`
- `DB_PASSWORD`
- `DB_HOST`
- `DB_PORT`
- `PASSWORD_RESET_TOKEN_EXPIRY_DAYS`
- `PASSWORD_RESET_FE_URL`
- `EMAIL_BACKEND`
- `EMAIL_HOST`
- `EMAIL_PORT`
- `EMAIL_USE_TLS`
- `EMAIL_HOST_USER`
- `EMAIL_HOST_PASSWORD`
- `DEFAULT_FROM_EMAIL`
- `SUPERUSER_EMAIL`
- `SUPERUSER_PASSWORD`
- `STRIPE_SECRET`
- `STRIPE_WEBHOOK`
- `1UP_CLIENT_ID`
- `1UP_CLIENT_SECRET`
- `1UP_BASE_URL`
- `CSRF_TRUSTED_ORIGINS`
- `CORS_ALLOWED_ORIGINS`
- `ALLOWED_HOSTS`
- `AWS_SQS_REGION`
- `AWS_SQS_ACCESS_KEY_ID`
- `AWS_SQS_SECRET_ACCESS_KEY`
- `AWS_SQS_GENERAL_URL`
- `AWS_SQS_QUEUE`
- `AWS_SQS_CONDITION_QUEUE`
- `AWS_SQS_ENCOUNTER_QUEUE`
- `AWS_SQS_MEDICATION_REQUEST_QUEUE`
- `AWS_SQS_DOCUMENT_REFERENCE_QUEUE`
- `CELERY_RESULT_BACKEND`
- `DELAY_TIME_IN_SEC`
- `WS_REDIS_HOST`
- `WS_REDIS_PORT`
- `WS_REDIS_PASSWORD`
- `S3_BUCKET_NAME`
- `S3_ACCESS_KEY`
- `S3_SECRET_KEY`
- `S3_BUCKET_FOLDER_PREFIX`
- `AWS_S3_SIGNATURE_VERSION`
- `BEEK_NOTIFICATION_API`
- `GENERATE_AUTH_CODE_URL`
- `GENERATE_ACCESS_TOKEN_URL`
- `BULK_DATA_EXPORT_URL`
- `BACKEND_URL`
- `FE_URL`
- `EMAIL_RESET_FE_URL`
- `EMAIL_VERIFICATION_FE_URL`
- `ACCESS_TOKEN_LIFETIME_IN_MINUTES`
- `ACTIVATION_TOKEN_EXPIRY_HOURS`
- `FREE_TRIAL_PERIOD_IN_DAYS`
- `AWS_S3_CUSTOM_DOMAIN`

---

## Conclusion

As mentioned in the beginning, proper configuration of environment variables is crucial for the seamless operation of the Beek application. Ensure that all required variables are set correctly and securely.