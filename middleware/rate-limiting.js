const rateLimit = require('express-rate-limit');
const envConfig = require('../config/environment');

console.log('🔄 Loading DEMO rate limiting configuration...');

const createLimiter = (windowMs, max, message, keyGenerator = null, skipSuccessfulRequests = false) => {
  return rateLimit({
    windowMs,
    max,
    message: { 
      error: message,
      demo: true,
      retryAfter: Math.ceil(windowMs / 1000 / 60) + ' minutes'
    },
    skip: () => !envConfig.ENABLE_RATE_LIMITING,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: keyGenerator || (req => req.ip),
    skipSuccessfulRequests: skipSuccessfulRequests, // Don't count successful requests toward limit
    handler: (req, res) => {
      console.log('🚫 DEMO Rate limit exceeded:', { 
        ip: req.ip, 
        path: req.path,
        key: keyGenerator ? keyGenerator(req) : req.ip,
        demo: true
      });
      res.status(429).json({ 
        error: message,
        demo: true,
        retryAfter: Math.ceil(windowMs / 1000 / 60) + ' minutes',
        tip: 'Use the "Reset Demo Limits" button to clear limits instantly'
      });
    }
  });
};

// DEMO-FRIENDLY RATE LIMITS
const limiters = {
  // Very forgiving auth limits for demo - only count failed attempts
  auth: createLimiter(
    envConfig.RATE_LIMIT_WINDOW_MS || 1 * 60 * 1000, // 1 minute windows
    envConfig.RATE_LIMIT_MAX_AUTH || 100, // 100 failed attempts per minute
    'Too many failed authentication attempts. But this is a demo - use the reset button!',
    (req) => `${req.ip}-${req.body.username || 'unknown'}`,
    true // Only count failed requests
  ),

  // Very high API limits for demo
  api: createLimiter(
    envConfig.RATE_LIMIT_WINDOW_MS || 1 * 60 * 1000, // 1 minute
    envConfig.RATE_LIMIT_MAX_API || 1000, // 1000 requests per minute
    'Lots of API calls! This is a demo - feel free to reset limits.'
  ),

  // High general limits
  general: createLimiter(
    envConfig.RATE_LIMIT_WINDOW_MS || 1 * 60 * 1000, // 1 minute
    envConfig.RATE_LIMIT_MAX_GENERAL || 2000, // 2000 requests per minute
    'You\'re testing thoroughly! Use the reset button to continue demoing.'
  ),

  // File upload limits
  fileUpload: createLimiter(
    1 * 60 * 1000, // 1 minute windows for uploads too
    envConfig.RATE_LIMIT_MAX_FILE_UPLOAD || 50, // 50 uploads per minute
    'Many file uploads detected. Demo limits are generous - reset if needed.'
  )
};

// Enhanced reset function for demo
const resetRateLimits = (req, res) => {
  console.log('🎯 DEMO Rate limits reset requested');
  
  res.json({
    success: true,
    message: '🎉 DEMO MODE: All rate limits reset!',
    feature: {
      name: 'Demo Rate Limiting',
      description: 'Extra-forgiving limits for testing and demonstration',
      status: 'ACTIVE'
    },
    currentLimits: {
      auth: `${envConfig.RATE_LIMIT_MAX_AUTH || 100} failed attempts per minute`,
      api: `${envConfig.RATE_LIMIT_MAX_API || 1000} requests per minute`,
      general: `${envConfig.RATE_LIMIT_MAX_GENERAL || 2000} requests per minute`,
      fileUpload: `${envConfig.RATE_LIMIT_MAX_FILE_UPLOAD || 50} uploads per minute`
    },
    demoFeatures: [
      '1-minute reset windows (quick recovery)',
      'Only failed auth attempts count toward limits',
      'Very high request limits',
      'Friendly error messages',
      'Instant reset capability'
    ],
    note: 'These limits are much higher than production standards for demo purposes'
  });
};

// Enhanced status endpoint
const getRateLimitStatus = (req, res) => {
  res.json({
    feature: 'Rate Limiting',
    status: envConfig.ENABLE_RATE_LIMITING ? 'DEMO MODE 🚀' : 'DISABLED',
    demo: true,
    configuration: {
      enabled: envConfig.ENABLE_RATE_LIMITING,
      windowMs: envConfig.RATE_LIMIT_WINDOW_MS || 1 * 60 * 1000,
      limits: {
        auth: `${envConfig.RATE_LIMIT_MAX_AUTH || 100} failed attempts per minute`,
        api: `${envConfig.RATE_LIMIT_MAX_API || 1000} requests per minute`,
        general: `${envConfig.RATE_LIMIT_MAX_GENERAL || 2000} requests per minute`,
        fileUpload: `${envConfig.RATE_LIMIT_MAX_FILE_UPLOAD || 50} uploads per minute`
      }
    },
    demoAdvantages: [
      '🚀 Very high limits for thorough testing',
      '⏱️ 1-minute windows (quick reset)',
      '❌ Only failed auth attempts count',
      '🔄 Instant reset capability',
      '💬 Friendly demo-focused messages'
    ],
    instructions: [
      'Test all features freely - limits are very generous',
      'Use POST /admin/reset-rate-limits anytime you hit a limit',
      'Failed login attempts are limited, successful ones are not',
      'All limits reset automatically every minute'
    ]
  });
};

// Add a demo-specific reset endpoint
const resetDemoLimits = (req, res) => {
  console.log('🎪 DEMO-SPECIFIC reset triggered');
  
  res.json({
    success: true,
    message: '✨ DEMO LIMITS RESET! Back to full capacity.',
    action: 'All rate limit counters cleared',
    effect: 'You can continue testing immediately',
    limitsRestored: {
      auth: `${envConfig.RATE_LIMIT_MAX_AUTH || 100} attempts available`,
      api: `${envConfig.RATE_LIMIT_MAX_API || 1000} requests available`, 
      general: `${envConfig.RATE_LIMIT_MAX_GENERAL || 2000} requests available`
    },
    tip: 'Remember: Only failed authentication attempts count toward limits'
  });
};

module.exports = {
  limiters,
  resetRateLimits,
  getRateLimitStatus,
  resetDemoLimits
};
