PRO FASTAPI AUTH SYSTEM (JWT + SMTP + ASYNC)
============================================

1. FEATURES:
   - Modern "Floating Label" UI (as requested)
   - Async Database (aiosqlite)
   - JWT stateless authentication (HttpOnly Cookies)
   - SMTP Integration for "Forgot Password" (Google App Password support)
   - Secure Password Hashing (Bcrypt)

2. SETUP:
   - Install: pip install fastapi[all] sqlalchemy aiosqlite passlib[bcrypt] python-jose[cryptography]
   - Edit SMTP_SETTINGS in main.py with your email and App Password.
   - Run: python main.py

3. USAGE:
   - Register at /register
   - Login at /login
   - Use /forgot to test the SMTP mailing system.

   Updated these lines
