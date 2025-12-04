const envConfig = require('./environment');

const securityConfig = {
  helmet: {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
      },
    },
    hsts: envConfig.NODE_ENV === 'production',
    crossOriginEmbedderPolicy: false
  },
  
  session: {
    secret: envConfig.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: envConfig.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: 'strict'
    },
    name: 'authDemoSession',
    rolling: true
  },
  
  // FIXED: Use proper CSRF configuration
  csrf: {
    cookie: false, // Don't use cookie-based CSRF tokens
    sessionKey: 'session' // Use session for CSRF token storage
  },
  
  cors: envConfig.CORS_ORIGIN ? {
    origin: envConfig.CORS_ORIGIN === 'true' ? true : envConfig.CORS_ORIGIN,
    credentials: true,
    optionsSuccessStatus: 200
  } : false
};

module.exports = securityConfig;