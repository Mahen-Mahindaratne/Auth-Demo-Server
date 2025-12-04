# Auth Demo Server

A comprehensive authentication and security demonstration server built with Node.js and Express. This project showcases multiple authentication methods, security features, and rate limiting mechanisms in a configurable, demo-friendly environment.
## 🚀 Features
### Authentication Methods

- Basic Authentication - HTTP Basic Auth with database validation

- Passport Local - Session-based authentication with Passport.js

- JWT Authentication - Stateless token-based authentication

- Multi-Factor Authentication - Key file validation for enhanced security

### Security Features

- Rate Limiting - Prevent brute force attacks with configurable limits

- Input Validation - Robust input sanitization with express-validator

- Security Headers - HTTP security headers with Helmet.js

- CSRF Protection - Form security for web applications

- File Upload Protection - Secure file uploads with validation and limits

### Demo-Friendly Features

- 🚀 Very high limits for thorough testing

- ⏱️ 1-minute rate limit windows (quick automatic reset)

- ❌ Only failed auth attempts count toward limits

- 🔄 Instant reset capability via endpoints

- 💬 Friendly demo-focused error messages

## 📦 Installation

- Clone the repository:

```bash

git clone <repository-url>
cd auth-demo-server
```
- Install dependencies:

```bash
npm install
```
- Set up environment variables:

```bash
cp .env.example .env
```
- Edit .env with your configuration

- Start the server:

```bash
# Development mode
npm run dev

# Production mode
npm start

# Or directly
node server.js
```

## 🔧 Configuration

The server is highly configurable through environment variables:
Core Settings

- PORT - Server port (default: 3000)

- NODE_ENV - Environment (development/production)

- SESSION_SECRET - Session encryption secret

## Feature Toggles

- ENABLE_BASIC_AUTH - Enable HTTP Basic Authentication

- ENABLE_PASSPORT_LOCAL - Enable Passport Local authentication

- ENABLE_JWT - Enable JWT authentication

- ENABLE_KEY_VALIDATION - Enable key file validation

- ENABLE_RATE_LIMITING - Enable rate limiting

- ENABLE_VALIDATION - Enable input validation

- ENABLE_HELMET - Enable security headers

- ENABLE_CSRF - Enable CSRF protection

- Rate Limiting (Demo Mode Defaults)

- RATE_LIMIT_MAX_AUTH - 100 failed attempts per minute

- RATE_LIMIT_MAX_API - 1000 requests per minute

- RATE_LIMIT_MAX_GENERAL - 2000 requests per minute

- RATE_LIMIT_MAX_FILE_UPLOAD - 50 uploads per minute

- RATE_LIMIT_WINDOW_MS - 60000ms (1 minute)

## JWT Configuration

- JWT_SECRET - JWT signing secret
- JWT_EXPIRES_IN - Token expiration time (default: 24h)

## 👥 Default Users

The server comes with three demo users:

### demo (DemoPass123!)

Demo user with key file requirement

- Requires key file: demo-key.txt with content demo-key-content

### admin (AdminPass456!)

Administrator with full access

- Requires key file: admin-key.txt with content admin-key-content

### user (UserPass789!)

Regular user without key file

- No key file required

## 📚 API Endpoints
### Basic Endpoints

- GET / - Welcome message and endpoint list

- GET /test - Basic server test

- GET /health - Health check with feature status

- GET /features - Comprehensive features overview

### Authentication Endpoints
#### Basic Auth

- GET /api/basic-auth-demo - Protected endpoint (requires Basic Auth)

- GET /api/basic-auth-status - Basic Auth status and instructions

#### Passport Local

- GET /login - Login instructions and CSRF token info

- POST /login - Login endpoint (requires CSRF token)

- GET /profile - Protected user profile (requires login)

- GET /logout - Logout endpoint

#### JWT Authentication

- POST /api/jwt-login - Get JWT token (supports key files)

- GET /api/jwt-protected - JWT protected endpoint

- GET /api/jwt-token-info - Decode JWT token

- GET /api/jwt-status - JWT configuration and instructions

#### Web Authentication

- GET /web/login - Web login form instructions

- GET /api/csrf-token - Get CSRF token for web forms

### Security & Monitoring

- POST /upload-demo - File upload rate limiting demo

- GET /admin/dashboard - Admin dashboard (JWT required)

- GET /admin/analytics - Request analytics (JWT required)

### Demo Controls

- POST /api/demo/reset-limits - Reset all rate limits

- GET /api/demo/status - Check demo mode status

- POST /admin/reset-rate-limits - Reset rate limits

- GET /api/rate-limit-info - Rate limiting configuration

## 🎯 Testing Interface

The project includes a comprehensive web-based testing interface (index.html) with:

- Demo Controls - Activate demo mode, reset limits, check status

- Test Endpoints - Test basic server endpoints

- Basic Auth Testing - Test HTTP Basic Authentication

- JWT Testing - Get and test JWT tokens with key file support

- Web Login Testing - Test Passport Local authentication

- CSRF Testing - Get CSRF tokens for form submissions

- Rate Limit Testing - Check and reset rate limits

## 🔒 Security Implementation
#### Rate Limiting Strategy

- Auth Endpoints: Limits failed login attempts

- API Endpoints: Limits API requests

- General Requests: Limits all other requests

- File Uploads: Limits file upload operations

- Demo Mode: Very high limits with 1-minute windows

#### Input Validation

- Username validation (3-30 characters)

- Password validation (minimum 6 characters)

- File upload validation (type and size limits)

- CSRF token validation for web forms

#### Security Headers (Helmet)

- Content Security Policy (CSP)

- XSS Protection

- No Sniff MIME type

- Hide Powered-By header

- HSTS enforcement (in production)

## 🏗️ Project Structure
```text

auth-demo-server/
├── server.js               
├── package.json            
├── .env.example            
├── config/
│   ├── environment.js      #
│   └── security.js         #
├── middleware/
│   └──rate-limiting.js     #
├── utils/
│   ├──database.js          #
│   ├──jwt-utils.js         #
│   └──request-logger.js    #
└── public/
    └── index.html           
```

## 📊 Monitoring & Analytics

The server includes built-in monitoring:

- Request logging with timestamps and IP addresses

- Endpoint usage statistics

- Error tracking and reporting

- Performance metrics

- Admin dashboard for real-time monitoring

## 🎮 Demo Mode

Demo mode is specifically designed for testing and presentation:

### Key Features

- High Limits: Test extensively without hitting limits

- Quick Reset: 1-minute windows for rapid testing cycles

- Selective Counting: Only failed attempts count toward auth limits

- Reset Endpoints: Instant reset capability

- Friendly Messages: Clear, helpful error messages

### Demo Endpoints

- POST /api/demo/reset-limits - Reset all limits instantly

- GET /api/demo/status - Check demo configuration

- POST /admin/reset-rate-limits - Reset rate limit counters

## 🔑 Key File Authentication

- Some users require key files for authentication:

### How It Works

- User attempts login with username and password

- Server checks if user requires key file

- If required, user must upload matching key file

- Server validates file content hash against stored hash

- Authentication proceeds only if all factors are valid

### Creating Key Files

For demo users:
```bash

# demo user
echo "demo-key-content" > demo-key.txt

# admin user  
echo "admin-key-content" > admin-key.txt
```
## 🚨 Error Handling

The server provides comprehensive error handling:

- Validation errors with detailed messages

- Authentication errors with specific error types

- Rate limiting errors with retry information

- CSRF errors with instructions

- Server errors with request IDs for debugging

## 📝 Testing Tips

- Start with Demo Mode: Use demo controls to set high limits

- Test All Methods: Try Basic Auth, JWT, and Passport Local

- Use Key Files: Test multi-factor authentication

- Check Rate Limits: Monitor rate limiting behavior

- Explore Admin Features: Use JWT token to access admin dashboard

- Test Error Cases: Try invalid credentials, missing key files, etc.

## 🔧 Development
Scripts
```bash

npm start          # Start server in production mode
npm run dev        # Start with nodemon for development
npm run production # Start in production environment
```

### Adding New Features

- Add feature toggle to environment configuration

- Implement feature with proper error handling

- Add to features endpoint for discovery

- Update README and testing interface

## 🤝 Contributing

- Fork the repository

- Create a feature branch

- Make your changes

- Add tests if applicable

- Submit a pull request

## 📄 License
ISC License. For secure authentication implementations only.

## ⚠️ Disclaimer
**This project is for educational and demonstration purposes.**

This is a demonstration server only. While it implements security features, it should not be used in production without thorough security review and appropriate hardening for your specific use case.

## 🙏 Acknowledgments

- Express.js team for the fantastic web framework

- Passport.js for authentication middleware

- All open-source contributors to the dependencies

**Happy Testing! 🎯🔒🚀**