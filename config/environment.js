require('dotenv').config();

const envConfig = {
  // Server
  NODE_ENV: process.env.NODE_ENV || 'development',
  PORT: process.env.PORT || 3000,
  
  // Security
  SESSION_SECRET: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
  JWT_SECRET: process.env.JWT_SECRET || 'jwt-dev-secret-change-in-production',
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '24h',
  
  // Feature Flags
  ENABLE_BASIC_AUTH: process.env.ENABLE_BASIC_AUTH !== 'false',
  ENABLE_PASSPORT_LOCAL: process.env.ENABLE_PASSPORT_LOCAL !== 'false',
  ENABLE_KEY_VALIDATION: process.env.ENABLE_KEY_VALIDATION !== 'false',
  ENABLE_JWT: process.env.ENABLE_JWT !== 'false',
  ENABLE_CSRF: process.env.ENABLE_CSRF !== 'false',
  ENABLE_RATE_LIMITING: process.env.ENABLE_RATE_LIMITING !== 'false',
  ENABLE_VALIDATION: process.env.ENABLE_VALIDATION !== 'false',
  ENABLE_HELMET: process.env.ENABLE_HELMET !== 'false',
  
  // FIXED: Proper TRUST_PROXY handling
  TRUST_PROXY: (() => {
    const value = process.env.TRUST_PROXY;
    if (value === undefined || value === null) return false;
    if (value === 'false' || value === '0') return false;
    if (value === 'true' || value === '1') return true;
    if (value === 'uniquelocal') return 'uniquelocal';
    return value; // Could be IP range, number, or string
  })(),
  
  CORS_ORIGIN: process.env.CORS_ORIGIN || false,
  
  // Rate Limiting
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  RATE_LIMIT_MAX_AUTH: parseInt(process.env.RATE_LIMIT_MAX_AUTH) || 5,
  RATE_LIMIT_MAX_API: parseInt(process.env.RATE_LIMIT_MAX_API) || 100,
  RATE_LIMIT_MAX_GENERAL: parseInt(process.env.RATE_LIMIT_MAX_GENERAL) || 200,
  
  // Users Configuration
  USERS: process.env.USERS || 'demo:DemoPass123!:demo-key-content:Demo User,admin:AdminPass456!:admin-key-content:Admin User,user:UserPass789!:no-key-file-user:Regular User'
};

// Parse users from environment
envConfig.PARSED_USERS = envConfig.USERS.split(',').map(userConfig => {
  const [username, password, keyFile, description] = userConfig.split(':');
  return {
    username: username?.trim(),
    password: password?.trim(),
    keyFile: keyFile?.trim() === 'no-key-file-user' ? null : keyFile?.trim(),
    description: description?.trim() || 'User'
  };
}).filter(user => user.username && user.password);

// Validate production requirements
if (envConfig.NODE_ENV === 'production') {
  const required = ['SESSION_SECRET', 'JWT_SECRET'];
  const missing = required.filter(envVar => !process.env[envVar]);
  if (missing.length > 0) {
    console.error('❌ Missing required environment variables in production:', missing);
    process.exit(1);
  }
}

module.exports = envConfig;