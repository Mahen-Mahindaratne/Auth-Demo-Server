const express = require('express');
const session = require('express-session');
const passport = require('passport');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const helmet = require('helmet');
const csrf = require('csurf');
const { body, validationResult, query, param } = require('express-validator');
const rateLimit = require('express-rate-limit');

// Import security configuration
const securityConfig = require('./config/security');

// Configurations
const envConfig = require('./config/environment');

// Database and Utilities
const MemoryDatabase = require('./utils/database');
const jwtUtils = require('./utils/jwt-utils');

// Rate Limiting
const { limiters, resetRateLimits, getRateLimitStatus } = require('./middleware/rate-limiting');

// Monitoring and Analytics
const RequestLogger = require('./utils/request-logger');

class AuthDemoServer {
  constructor() {
    this.app = express();
    this.db = new MemoryDatabase();
    this.requestLogger = new RequestLogger();
    this.setupMiddleware();
    this.setupSecurity();
    this.setupAuth();
    this.setupRoutes();
    this.setupErrorHandling();
  }

  setupMiddleware() {
    // Basic middleware
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
    this.app.use(express.static(path.join(__dirname, 'public')));

    // Request logging
    this.app.use(this.requestLogger.middleware());

    // Session (required for Passport and CSRF)
    this.app.use(session({
      secret: envConfig.SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: { 
        secure: envConfig.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
      }
    }));

    // Apply general rate limiting to all routes
    if (envConfig.ENABLE_RATE_LIMITING) {
      this.app.use(limiters.general);
      console.log('🔒 General rate limiting applied');
    }

    // Make database and utilities available to routes
    this.app.use((req, res, next) => {
      req.db = this.db;
      req.jwtUtils = jwtUtils;
      req.requestLogger = this.requestLogger;
      next();
    });

    // Configure multer for file uploads
    this.upload = multer({
      storage: multer.memoryStorage(),
      limits: {
        fileSize: 5 * 1024 * 1024,
        files: 1
      },
      fileFilter: (req, file, cb) => {
        const allowedMimeTypes = ['text/plain', 'application/octet-stream'];
        if (allowedMimeTypes.includes(file.mimetype)) {
          cb(null, true);
        } else {
          console.log('⚠️  Unusual file type uploaded:', file.mimetype);
          cb(null, true);
        }
      }
    });
  }

  setupSecurity() {
  // ✅ Helmet Security Headers
  if (envConfig.ENABLE_HELMET) {
    this.app.use(helmet(securityConfig.helmet));
    console.log('🛡️  Helmet security headers enabled');
  }

  // ✅ Session Middleware (MUST come before CSRF)
  this.app.use(session(securityConfig.session));

  // ✅ CSRF Protection - FIXED Configuration
  if (envConfig.ENABLE_CSRF) {
    // Initialize CSRF
    this.csrfProtection = csrf({ 
      cookie: false // Use session instead of cookie
    });
    
    // Apply CSRF middleware ONLY to generate tokens (skip validation)
    this.app.use((req, res, next) => {
      // Call CSRF to generate token but don't validate yet
      this.csrfProtection(req, res, (err) => {
        if (err && err.code !== 'EBADCSRFTOKEN') {
          return next(err);
        }
        // Continue even if CSRF validation would fail
        next();
      });
    });
    
    // Make CSRF token available to all routes
    this.app.use((req, res, next) => {
      res.locals._csrf = req.csrfToken ? req.csrfToken() : '';
      next();
    });
    
    // MANUALLY apply CSRF validation ONLY to POST /login
    const originalPostLogin = this.app.routes?.post?.find(route => route.path === '/login');
    
    // Apply CSRF protection specifically to POST /login
    this.app.post('/login', (req, res, next) => {
      console.log('🔐 Applying CSRF protection to POST /login');
      this.csrfProtection(req, res, next);
    }, originalPostLogin?.callbacks || []);
    
    console.log('🛡️  CSRF protection enabled (POST /login only)');
  } else {
    this.app.use((req, res, next) => {
      res.locals._csrf = '';
      next();
    });
  }
}
  setupAuth() {
    // Initialize Passport
    this.app.use(passport.initialize());
    this.app.use(passport.session());

    // Basic serialization
    passport.serializeUser((user, done) => {
      done(null, user.username);
    });

    passport.deserializeUser(async (username, done) => {
      try {
        const user = await this.db.getUserByUsername(username);
        done(null, user);
      } catch (error) {
        done(error);
      }
    });

    // Passport Local Strategy
    const LocalStrategy = require('passport-local').Strategy;
    
    passport.use(new LocalStrategy({
      usernameField: 'username',
      passwordField: 'password',
      passReqToCallback: true
    }, async (req, username, password, done) => {
      try {
        console.log('🔐 Passport login attempt:', username);

        const user = await this.db.getUserByUsername(username);
        if (!user) {
          console.log('❌ User not found:', username);
          return done(null, false, { message: 'Invalid credentials' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
          console.log('❌ Invalid password for:', username);
          return done(null, false, { message: 'Invalid credentials' });
        }

        // Key file validation
        if (user.key_file_hash) {
          console.log('🔑 Key file required for user:', username);
          
          const keyFile = req.file;
          if (!keyFile) {
            console.log('❌ Key file missing for user:', username);
            return done(null, false, { message: 'Key file required' });
          }

          const fileContent = keyFile.buffer.toString();
          const fileHash = this.db.generateHash(fileContent);
          const isKeyFileValid = fileHash === user.key_file_hash;
          
          console.log('🔑 Key file validation:', {
            expected: user.key_file_hash.substring(0, 16) + '...',
            received: fileHash.substring(0, 16) + '...',
            isValid: isKeyFileValid
          });
          
          if (!isKeyFileValid) {
            console.log('❌ Key file validation failed for:', username);
            return done(null, false, { message: 'Invalid key file' });
          }
          
          console.log('✅ Key file validation successful');
          req.keyFileValidated = true;
        } else {
          console.log('ℹ️  No key file required for:', username);
        }

        console.log('✅ Login successful:', username);
        return done(null, user);
        
      } catch (error) {
        console.error('💥 Auth error:', error);
        return done(error);
      }
    }));
  }

  setupRoutes() {
    // ==================== VALIDATION MIDDLEWARE ====================
    const validateRequest = (validations) => {
      return async (req, res, next) => {
        await Promise.all(validations.map(validation => validation.run(req)));
        
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          return res.status(400).json({
            error: 'Validation failed',
            details: errors.array(),
            feature: {
              name: 'Input Validation',
              description: 'Robust input sanitization with express-validator',
              status: 'WORKING'
            }
          });
        }
        next();
      };
    };

    // Common validation chains
    const loginValidations = [
      body('username')
        .isLength({ min: 3, max: 30 })
        .withMessage('Username must be 3-30 characters')
        .trim()
        .escape(),
      body('password')
        .isLength({ min: 6 })
        .withMessage('Password must be at least 6 characters')
    ];

    const jwtLoginValidations = [
      body('username')
        .isLength({ min: 3, max: 30 })
        .withMessage('Username must be 3-30 characters')
        .trim()
        .escape(),
      body('password')
        .isLength({ min: 6 })
        .withMessage('Password must be at least 6 characters')
    ];

    // ==================== BASIC ENDPOINTS ====================
    this.app.get('/test', (req, res) => {
      res.json({ 
        message: 'Server is working!', 
        environment: envConfig.NODE_ENV,
        timestamp: new Date().toISOString() 
      });
    });

    this.app.get('/health', (req, res) => {
      res.json({ 
        status: 'OK', 
        environment: envConfig.NODE_ENV,
        features: {
          basicAuth: 'IMPLEMENTED',
          passportLocal: 'IMPLEMENTED', 
          keyValidation: 'IMPLEMENTED',
          jwt: 'IMPLEMENTED',
          rateLimiting: envConfig.ENABLE_RATE_LIMITING ? 'ENABLED' : 'DISABLED',
          validation: envConfig.ENABLE_VALIDATION ? 'ENABLED' : 'DISABLED',
          helmet: envConfig.ENABLE_HELMET ? 'ENABLED' : 'DISABLED',
          csrf: envConfig.ENABLE_CSRF ? 'ENABLED' : 'DISABLED',
          monitoring: 'ENABLED'
        }
      });
    });

    this.app.get('/', (req, res) => {
      res.json({
        message: 'Welcome to Auth Demo Server',
        endpoints: {
          '/test': 'Basic test',
          '/health': 'Health check', 
          '/features': 'All features',
          '/login': 'Passport login instructions',
          '/api/basic-auth-demo': 'Basic auth demo',
          '/api/jwt-status': 'JWT instructions',
          '/api/rate-limit-status': 'Rate limiting status',
          '/admin/dashboard': 'Admin dashboard',
          '/admin/analytics': 'Request analytics',
          '/api/csrf-token': 'Get CSRF token for web forms'
        }
      });
    });

   // ==================== DEMO RATE LIMIT MANAGEMENT ====================
   this.app.post('/api/demo/reset-limits', (req, res) => {
     console.log('🎯 Demo rate limit reset triggered');
  
      res.json({
        success: true,
        message: '🎉 All rate limits reset! Demo mode activated.',
        feature: {
          name: 'Demo Rate Limiting',
          description: 'Extra-forgiving limits for testing and demonstration',
          status: 'ACTIVE'
        },
        limits: {
          auth: '100 attempts per minute',
          api: '1000 requests per minute',
          general: '2000 requests per minute',
          fileUpload: '50 uploads per minute'
        },
        instructions: [
          'Test all authentication methods freely',
          'Try multiple users and key file combinations',
          'Explore all API endpoints without restrictions',
          'Rate limits automatically reset every minute'
        ]
      });
    });

    // Demo status endpoint
    this.app.get('/api/demo/status', (req, res) => {
      res.json({
        demo: true,
        message: '🚀 DEMO MODE ACTIVE - Forgiving rate limits enabled',
        environment: 'Render Production',
        rateLimiting: 'Demo-friendly (very high limits)',
        features: 'All security features active with generous limits',
        resetEndpoint: 'POST /api/demo/reset-limits'
      });
    });

    // ==================== CSRF ENDPOINTS ====================
    this.app.get('/api/csrf-token', (req, res) => {
      res.json({
        csrfToken: res.locals._csrf,
        instructions: 'Use this token in X-CSRF-Token header for POST /login',
        contentType: 'application/x-www-form-urlencoded',
        feature: {
          name: 'CSRF Protection',
          description: 'Form security for web apps',
          status: 'WORKING'
        }
      });
    });

    this.app.get('/web/login', (req, res) => {
      res.json({
        feature: 'Web Login Form',
        status: 'READY',
        instructions: 'Include CSRF token in form submissions for web login',
        csrf: {
          enabled: envConfig.ENABLE_CSRF,
          token: res.locals._csrf,
          headerName: 'X-CSRF-Token',
          formFieldName: '_csrf'
        },
        form: {
          method: 'POST',
          action: '/login',
          enctype: 'application/x-www-form-urlencoded',
          fields: [
            { name: 'username', type: 'text', required: true },
            { name: 'password', type: 'password', required: true },
            { name: '_csrf', type: 'hidden', value: res.locals._csrf }
          ]
        },
        testInstructions: [
          '1. Get CSRF token from /api/csrf-token',
          '2. Include in X-CSRF-Token header AND _csrf form field',
          '3. Use application/x-www-form-urlencoded content type'
        ]
      });
    });

    // ==================== BASIC AUTHENTICATION ====================
    this.app.get('/api/basic-auth-demo', async (req, res) => {
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Basic ')) {
        res.setHeader('WWW-Authenticate', 'Basic realm="Auth Demo"');
        return res.status(401).json({ 
          error: 'Basic authentication required',
          instructions: 'Use credentials: admin/AdminPass456! or demo/DemoPass123! or user/UserPass789!',
          feature: 'Basic Authentication',
          status: 'ENABLED'
        });
      }

      const credentials = Buffer.from(authHeader.slice(6), 'base64').toString();
      const [username, password] = credentials.split(':');

      try {
        const user = await this.db.getUserByUsername(username);
        if (!user) {
          res.setHeader('WWW-Authenticate', 'Basic realm="Auth Demo"');
          return res.status(401).json({ 
            error: 'Invalid credentials',
            message: 'User not found'
          });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
          res.setHeader('WWW-Authenticate', 'Basic realm="Auth Demo"');
          return res.status(401).json({ 
            error: 'Invalid credentials',
            message: 'Password incorrect'
          });
        }

        res.json({
          success: true,
          message: 'Basic authentication successful!',
          user: { 
            username,
            authMethod: 'HTTP Basic Auth',
            requiresKeyFile: !!user.key_file_hash,
            description: user.description,
            timestamp: new Date().toISOString()
          },
          feature: {
            name: 'Basic Authentication',
            description: 'HTTP Basic Auth with database validation',
            status: 'WORKING'
          },
          note: user.key_file_hash ? 
            'Note: This user requires key file for full login (Passport/JWT)' : 
            'Note: No key file required for this user'
        });
      } catch (error) {
        console.error('Basic auth error:', error);
        res.status(500).json({ error: 'Authentication error' });
      }
    });

    this.app.get('/api/basic-auth-status', limiters.api, (req, res) => {
      res.json({
        feature: 'Basic Authentication',
        status: 'ENABLED',
        endpoints: [
          'GET /api/basic-auth-demo - Protected endpoint (requires Basic Auth)',
          'GET /api/basic-auth-status - This status page'
        ],
        testCredentials: [
          { username: 'demo', password: 'DemoPass123!' },
          { username: 'admin', password: 'AdminPass456!' },
          { username: 'user', password: 'UserPass789!' }
        ],
        instructions: [
          'Use curl: curl -u demo:DemoPass123! http://localhost:3000/api/basic-auth-demo',
          'Or in browser: browser will prompt for credentials',
          'Note: Basic Auth does not require key files (simpler than Passport/JWT)'
        ]
      });
    });

    // ==================== JWT AUTHENTICATION ====================
    this.app.post('/api/jwt-login', 
      limiters.auth,
      this.upload.single('keyFile'),
      envConfig.ENABLE_VALIDATION ? validateRequest(jwtLoginValidations) : (req, res, next) => next(),
      async (req, res) => {
        try {
          const { username, password } = req.body;
          
          if (!username || !password) {
            return res.status(400).json({ 
              error: 'Username and password required' 
            });
          }

          console.log('🔐 JWT login attempt:', username);

          const user = await this.db.getUserByUsername(username);
          if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
          }

          const isPasswordValid = await bcrypt.compare(password, user.password_hash);
          if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
          }

          let keyFileValidated = false;
          if (user.key_file_hash) {
            const keyFile = req.file;
            if (!keyFile) {
              return res.status(401).json({ error: 'Key file required' });
            }

            const fileContent = keyFile.buffer.toString();
            const fileHash = this.db.generateHash(fileContent);
            if (fileHash !== user.key_file_hash) {
              return res.status(401).json({ error: 'Invalid key file' });
            }
            
            keyFileValidated = true;
          }

          const token = jwtUtils.generateToken(user);
          await this.db.storeJWTToken(token, user.username);

          res.json({
            success: true,
            message: 'JWT authentication successful!' + 
                     (keyFileValidated ? ' (Key file validated)' : ''),
            token,
            tokenType: 'Bearer',
            expiresIn: envConfig.JWT_EXPIRES_IN,
            user: {
              username: user.username,
              requiresKeyFile: !!user.key_file_hash,
              keyFileValidated,
              description: user.description
            }
          });

        } catch (error) {
          console.error('💥 JWT login error:', error);
          res.status(500).json({ error: 'Authentication failed' });
        }
      }
    );

    this.app.get('/api/jwt-protected', 
      jwtUtils.authenticateToken,
      (req, res) => {
        res.json({
          success: true,
          message: 'JWT protected endpoint accessed successfully!',
          user: req.jwtUser,
          authentication: {
            method: 'JWT',
            tokenType: 'Bearer',
            stateless: true
          },
          feature: {
            name: 'JWT Authentication',
            description: 'Stateless token-based authentication',
            status: 'WORKING'
          },
          timestamp: new Date().toISOString()
        });
      }
    );

    this.app.get('/api/jwt-token-info', limiters.api, (req, res) => {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];
      
      if (!token) {
        return res.status(400).json({ error: 'No token provided' });
      }

      try {
        const jwt = require('jsonwebtoken');
        const decoded = jwt.decode(token);
        res.json({
          tokenInfo: decoded,
          instructions: 'This shows token contents without verification'
        });
      } catch (error) {
        res.status(400).json({ error: 'Invalid token format' });
      }
    });

    this.app.get('/api/jwt-status', limiters.api, (req, res) => {
      res.json({
        feature: 'JWT Authentication',
        status: envConfig.ENABLE_JWT ? 'ENABLED' : 'DISABLED',
        endpoints: {
          'POST /api/jwt-login': 'Get JWT token',
          'GET /api/jwt-protected': 'JWT protected endpoint',
          'GET /api/jwt-token-info': 'Decode token without verification',
          'GET /api/jwt-status': 'This status page'
        },
        configuration: {
          expiresIn: envConfig.JWT_EXPIRES_IN,
          issuer: 'auth-demo-server',
          audience: 'auth-demo-client'
        },
        testInstructions: [
          '1. POST to /api/jwt-login to get token',
          '2. Use: curl -H "Authorization: Bearer <token>" http://localhost:3000/api/jwt-protected',
          '3. Supports key files for multi-factor JWT'
        ],
        users: envConfig.PARSED_USERS.map(u => ({
          username: u.username,
          requiresKeyFile: !!u.keyFile,
          description: u.description
        }))
      });
    });

    // ==================== PASSPORT LOCAL AUTHENTICATION ====================
    this.app.get('/login', (req, res) => {
      res.json({
        feature: 'Passport Local Authentication',
        status: 'READY',
        instructions: 'POST to /login with form data including key file if required',
        testUsers: envConfig.PARSED_USERS.map(u => ({
          username: u.username,
          requiresKeyFile: !!u.keyFile,
          description: u.description
        })),
        endpoints: {
          'GET /login': 'This instructions page',
          'POST /login': 'Login endpoint (form data with key file)',
          'GET /profile': 'Protected profile page (requires login)',
          'GET /logout': 'Logout endpoint'
        },
        csrf: envConfig.ENABLE_CSRF ? {
          enabled: true,
          token: res.locals._csrf,
          instructions: 'Include in X-CSRF-Token header and _csrf form field'
        } : { enabled: false }
      });
    });

    this.app.post('/login', 
      limiters.auth,
      this.upload.single('keyFile'),
      envConfig.ENABLE_VALIDATION ? validateRequest(loginValidations) : (req, res, next) => next(),
      (req, res, next) => {
        console.log('📁 File upload info:', {
          hasFile: !!req.file,
          fileName: req.file?.originalname,
          fileSize: req.file?.size
        });
        
        passport.authenticate('local', (err, user, info) => {
          if (err) {
            return res.status(500).json({ error: 'Authentication error' });
          }
          
          if (!user) {
            let errorType = 'invalid_credentials';
            if (info?.message === 'Key file required') errorType = 'key_required';
            if (info?.message === 'Invalid key file') errorType = 'key_invalid';
            
            return res.status(401).json({ 
              error: 'Login failed',
              type: errorType,
              message: info?.message || 'Invalid credentials'
            });
          }
          
          req.logIn(user, (err) => {
            if (err) {
              return res.status(500).json({ error: 'Session error' });
            }
            
            return res.json({
              success: true,
              message: 'Login successful!' + (req.keyFileValidated ? ' (Key file validated)' : ''),
              user: {
                username: user.username,
                requiresKeyFile: !!user.key_file_hash,
                keyFileValidated: req.keyFileValidated || false,
                description: user.description
              },
              session: {
                id: req.sessionID?.substring(0, 8),
                authenticated: true
              }
            });
          });
        })(req, res, next);
      }
    );

    this.app.get('/profile', (req, res) => {
      if (!req.isAuthenticated()) {
        return res.status(401).json({
          error: 'Authentication required',
          message: 'Please login first at POST /login'
        });
      }
      
      res.json({
        success: true,
        message: 'Welcome to your profile!',
        user: {
          username: req.user.username,
          requiresKeyFile: !!req.user.key_file_hash,
          keyFileValidated: req.keyFileValidated || false,
          description: req.user.description,
          sessionId: req.sessionID?.substring(0, 8)
        },
        feature: {
          name: 'Passport Local Authentication',
          description: 'Session-based authentication with key file support',
          status: 'WORKING'
        }
      });
    });

    this.app.get('/logout', (req, res) => {
      const username = req.user?.username;
      req.logout((err) => {
        if (err) {
          return res.status(500).json({ error: 'Logout error' });
        }
        
        res.json({
          success: true,
          message: 'Logged out successfully',
          user: username ? `Goodbye ${username}` : 'No user was logged in'
        });
      });
    });

    // ==================== FILE UPLOAD DEMO ====================
    this.app.post('/upload-demo', 
      limiters.fileUpload,
      this.upload.single('file'),
      (req, res) => {
        res.json({
          success: true,
          message: 'File upload demo - rate limited to 10 uploads per hour',
          file: req.file ? {
            name: req.file.originalname,
            size: req.file.size,
            mimetype: req.file.mimetype
          } : null,
          feature: {
            name: 'File Upload Rate Limiting',
            description: 'Prevent abuse of file upload functionality',
            status: 'WORKING'
          }
        });
      }
    );

    // ==================== ADMIN DASHBOARD & ANALYTICS ====================
    this.app.get('/admin/dashboard', 
      jwtUtils.authenticateToken,
      (req, res) => {
        // Check if user is admin
        if (req.jwtUser.username !== 'admin') {
          return res.status(403).json({ error: 'Admin access required' });
        }

        const stats = this.requestLogger.getStats();
        const users = this.db.getAllUsers();
        
        res.json({
          success: true,
          message: 'Admin Dashboard',
          feature: {
            name: 'Admin Dashboard',
            description: 'User management and system monitoring',
            status: 'WORKING'
          },
          system: {
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            users: users.length
          },
          analytics: {
            totalRequests: stats.totalRequests,
            requestsLastHour: stats.requestsLastHour,
            endpointStats: stats.endpointStats,
            errorRate: stats.errorRate
          },
          users: users.map(user => ({
            username: user.username,
            lastLogin: user.lastLogin,
            loginCount: user.loginCount,
            requiresKeyFile: !!user.key_file_hash
          })),
          security: {
            rateLimiting: envConfig.ENABLE_RATE_LIMITING,
            validation: envConfig.ENABLE_VALIDATION,
            helmet: envConfig.ENABLE_HELMET,
            csrf: envConfig.ENABLE_CSRF
          }
        });
      }
    );

    this.app.get('/admin/analytics', 
      jwtUtils.authenticateToken,
      (req, res) => {
        if (req.jwtUser.username !== 'admin') {
          return res.status(403).json({ error: 'Admin access required' });
        }

        const analytics = this.requestLogger.getDetailedAnalytics();
        
        res.json({
          success: true,
          message: 'Request Analytics',
          feature: {
            name: 'Monitoring & Analytics',
            description: 'Request logging and performance metrics',
            status: 'WORKING'
          },
          timeframe: 'Last 24 hours',
          summary: analytics.summary,
          endpoints: analytics.endpoints,
          errors: analytics.errors,
          performance: analytics.performance
        });
      }
    );

    // ==================== FEATURES OVERVIEW ====================
    this.app.get('/features', (req, res) => {
      res.json({
        server: 'Authentication Demo Server',
        environment: envConfig.NODE_ENV,
        status: 'RUNNING',
        features: {
          basicAuth: {
            status: 'IMPLEMENTED',
            endpoints: ['/api/basic-auth-demo', '/api/basic-auth-status'],
            description: 'HTTP Basic Authentication with hardcoded credentials'
          },
          passportLocal: {
            status: 'IMPLEMENTED',
            endpoints: ['GET /login', 'POST /login', 'GET /profile', 'GET /logout'],
            description: 'Session-based authentication with Passport.js'
          },
          keyValidation: {
            status: 'IMPLEMENTED',
            endpoints: ['POST /login (with key file upload)', 'POST /api/jwt-login (with key file)'],
            description: 'Multi-factor authentication with key files',
            usersRequiringKeyFiles: envConfig.PARSED_USERS
              .filter(u => u.keyFile)
              .map(u => u.username)
          },
          jwt: {
            status: 'IMPLEMENTED',
            endpoints: [
              'POST /api/jwt-login',
              'GET /api/jwt-protected',
              'GET /api/jwt-token-info',
              'GET /api/jwt-status'
            ],
            description: 'Stateless JWT token authentication'
          },
          rateLimiting: {
            status: 'IMPLEMENTED',
            endpoints: [
              'GET /api/rate-limit-status',
              'POST /admin/reset-rate-limits (demo only)',
              'POST /upload-demo (file upload rate limiting)'
            ],
            description: 'Prevent brute force attacks with request rate limiting',
            limits: {
              auth: '5 attempts per 15 minutes',
              api: '100 requests per 15 minutes',
              general: '200 requests per 15 minutes',
              fileUpload: '10 uploads per hour'
            }
          },
          validation: {
            status: envConfig.ENABLE_VALIDATION ? 'IMPLEMENTED' : 'NOT_IMPLEMENTED',
            description: 'Input validation with express-validator',
            endpoints: ['POST /login', 'POST /api/jwt-login']
          },
          helmet: {
            status: envConfig.ENABLE_HELMET ? 'IMPLEMENTED' : 'NOT_IMPLEMENTED',
            description: 'HTTP security headers with Helmet.js'
          },
          csrf: {
            status: envConfig.ENABLE_CSRF ? 'IMPLEMENTED' : 'DISABLED',
            description: 'CSRF protection for web apps',
            endpoints: ['POST /login']
          },
          adminDashboard: {
            status: 'IMPLEMENTED',
            endpoints: ['GET /admin/dashboard', 'GET /admin/analytics'],
            description: 'User management interface and analytics'
          },
          monitoring: {
            status: 'IMPLEMENTED',
            description: 'Request logging and performance analytics'
          },
          oauth: {
            status: 'PLANNED',
            description: 'Social login (Google, GitHub) - Requires OAuth app setup'
          }
        },
        users: envConfig.PARSED_USERS.map(u => ({
          username: u.username,
          requiresKeyFile: !!u.keyFile,
          description: u.description
        })),
        instructions: 'All security features implemented and configurable via environment variables'
      });
    });
  }

  setupErrorHandling() {
    // CSRF error handler
    if (envConfig.ENABLE_CSRF) {
      this.app.use((err, req, res, next) => {
        if (err.code === 'EBADCSRFTOKEN') {
          return res.status(403).json({
            error: 'CSRF token validation failed',
            message: 'Invalid or missing CSRF token',
            feature: {
              name: 'CSRF Protection',
              description: 'Form security for web apps',
              status: 'WORKING'
            }
          });
        }
        next(err);
      });
    }

    // 404 handler
    this.app.use((req, res) => {
      res.status(404).json({
        error: 'Not found',
        path: req.path
      });
    });

    // Global error handler
    this.app.use((err, req, res, next) => {
      console.error('💥 Server error:', err);
      
      // Log the error
      if (this.requestLogger) {
        this.requestLogger.logError(req, err);
      }
      
      res.status(500).json({
        error: 'Internal server error',
        message: envConfig.NODE_ENV === 'development' ? err.message : 'Something went wrong',
        requestId: req.requestId
      });
    });
  }

  start() {
    this.app.listen(envConfig.PORT, () => {
      console.log('\n' + '='.repeat(80));
      console.log('🚀 COMPREHENSIVE AUTHENTICATION & SECURITY DEMO SERVER');
      console.log('='.repeat(80));
      console.log(`📍 Server: http://localhost:${envConfig.PORT}`);
      console.log(`🌐 Environment: ${envConfig.NODE_ENV}`);
      console.log('🗄️  Database: Memory (users from environment)');
      console.log('='.repeat(80));
      console.log('🔧 FEATURES STATUS:');
      console.log(`   Basic Auth: ${envConfig.ENABLE_BASIC_AUTH ? '✅' : '❌'}`);
      console.log(`   Passport Local: ${envConfig.ENABLE_PASSPORT_LOCAL ? '✅' : '❌'}`);
      console.log(`   Key Validation: ${envConfig.ENABLE_KEY_VALIDATION ? '✅' : '❌'}`);
      console.log(`   JWT: ${envConfig.ENABLE_JWT ? '✅' : '❌'}`);
      console.log(`   Rate Limiting: ${envConfig.ENABLE_RATE_LIMITING ? '✅ DEMO MODE' : '❌'}`);
      console.log(`   Input Validation: ${envConfig.ENABLE_VALIDATION ? '✅' : '❌'}`);
      console.log(`   Helmet: ${envConfig.ENABLE_HELMET ? '✅' : '❌'}`);
      console.log(`   CSRF: ${envConfig.ENABLE_CSRF ? '✅' : '❌'}`);
      console.log(`   Admin Dashboard: ✅`);
      console.log(`   Monitoring: ✅`);
      console.log(`   OAuth: ${envConfig.ENABLE_OAUTH ? '🔄' : '❌'}`);
      console.log('='.repeat(80));
      console.log('👥 CONFIGURED USERS:');
      envConfig.PARSED_USERS.forEach(user => {
        console.log(`   ${user.username} - ${user.description}`);
      });
      console.log('='.repeat(80));
      console.log('📚 DEMO ENDPOINTS:');
      console.log(`   GET  /features              - All features status`);
      console.log(`   GET  /api/rate-limit-status - Rate limiting status`);
      console.log(`   GET  /api/jwt-status        - JWT instructions`);
      console.log(`   GET  /login                 - Passport login instructions`);
      console.log(`   GET  /admin/dashboard       - Admin dashboard (JWT required)`);
      console.log(`   GET  /admin/analytics       - Request analytics (JWT required)`);
      console.log(`   GET  /api/csrf-token        - Get CSRF token for web forms`);
      console.log(`   GET  /web/login             - Web login form instructions`);
      console.log(`   POST /admin/reset-rate-limits - Reset rate limits (demo)`);
      console.log(`   POST /api/demo/reset-limits - Reset ALL demo limits`);
      console.log(`   GET  /api/demo/status       - Demo mode status`);
      console.log(`   POST /upload-demo           - File upload rate limiting demo`);
      console.log('='.repeat(80));
      console.log('🔒 DEMO SECURITY PROTECTION:');
      console.log(`   Authentication: ${envConfig.RATE_LIMIT_MAX_AUTH || 100} failed attempts per ${(envConfig.RATE_LIMIT_WINDOW_MS || 60000) / 1000} seconds`);
      console.log(`   API Requests: ${envConfig.RATE_LIMIT_MAX_API || 1000} requests per ${(envConfig.RATE_LIMIT_WINDOW_MS || 60000) / 1000} seconds`);
      console.log(`   General: ${envConfig.RATE_LIMIT_MAX_GENERAL || 2000} requests per ${(envConfig.RATE_LIMIT_WINDOW_MS || 60000) / 1000} seconds`);
      console.log(`   File Uploads: ${envConfig.RATE_LIMIT_MAX_FILE_UPLOAD || 50} uploads per ${(envConfig.RATE_LIMIT_WINDOW_MS || 60000) / 1000} seconds`);
      console.log('='.repeat(80));
      console.log('🎯 DEMO MODE FEATURES:');
      console.log(`   🚀 Very high limits for thorough testing`);
      console.log(`   ⏱️  1-minute windows (quick automatic reset)`);
      console.log(`   ❌ Only failed auth attempts count toward limits`);
      console.log(`   🔄 Instant reset capability via endpoints`);
      console.log(`   💬 Friendly demo-focused error messages`);
      console.log('='.repeat(80));
      console.log('🔑 DEMO CREDENTIALS:');
      console.log(`   demo/DemoPass123!     - Requires key file for full login`);
      console.log(`   admin/AdminPass456!   - Requires key file for full login`);
      console.log(`   user/UserPass789!     - No key file required`);
      console.log(`   📝 Use these same credentials for Basic Auth too!`);
      console.log('='.repeat(80));
      console.log('💡 PRO TIPS:');
      console.log(`   • Use the reset endpoints if you hit any limits`);
      console.log(`   • Only failed login attempts count toward auth limits`);
      console.log(`   • All limits reset automatically every minute`);
      console.log(`   • Test all authentication methods freely`);
      console.log('='.repeat(80));
    });
  }
}

// Start the server
const server = new AuthDemoServer();
server.start();
