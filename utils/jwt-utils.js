const jwt = require('jsonwebtoken');
const envConfig = require('../config/environment');

console.log('🔄 Loading JWT utilities...');
console.log('JWT Secret configured:', !!envConfig.JWT_SECRET);
console.log('JWT Expires In:', envConfig.JWT_EXPIRES_IN);

const jwtUtils = {
  // Generate JWT token
  generateToken: (user) => {
    console.log('🔐 Generating JWT token for user:', user.username);
    try {
      const payload = {
        userId: user.id,
        username: user.username,
        requiresKeyFile: !!user.key_file_hash,
        iat: Math.floor(Date.now() / 1000) // issued at
      };
      
      const token = jwt.sign(payload, envConfig.JWT_SECRET, {
        expiresIn: envConfig.JWT_EXPIRES_IN,
        issuer: 'auth-demo-server',
        audience: 'auth-demo-client'
      });
      
      console.log('✅ JWT token generated successfully');
      return token;
    } catch (error) {
      console.error('❌ Error generating JWT token:', error);
      return null;
    }
  },
  
  // Verify JWT token
  verifyToken: (token) => {
    console.log('🔍 Verifying JWT token...');
    try {
      const decoded = jwt.verify(token, envConfig.JWT_SECRET, {
        issuer: 'auth-demo-server',
        audience: 'auth-demo-client'
      });
      console.log('✅ JWT token verified successfully');
      return decoded;
    } catch (error) {
      console.log('❌ JWT verification failed:', error.message);
      return null;
    }
  },
  
  // JWT authentication middleware
  authenticateToken: (req, res, next) => {
    console.log('🛡️ JWT authentication middleware called');
    try {
      const authHeader = req.headers['authorization'];
      console.log('Authorization header:', authHeader);
      
      if (!authHeader) {
        console.log('❌ No authorization header');
        return res.status(401).json({ error: 'JWT token required' });
      }
      
      const token = authHeader.startsWith('Bearer ') 
        ? authHeader.slice(7) 
        : authHeader.split(' ')[1];
      
      console.log('Extracted token:', token ? `${token.substring(0, 20)}...` : 'none');
      
      if (!token) {
        console.log('❌ No token found in authorization header');
        return res.status(401).json({ error: 'JWT token required' });
      }
      
      const decoded = jwtUtils.verifyToken(token);
      if (!decoded) {
        console.log('❌ Token verification failed');
        return res.status(403).json({ error: 'Invalid or expired token' });
      }
      
      console.log('✅ JWT authentication successful for user:', decoded.username);
      req.jwtUser = decoded;
      next();
    } catch (error) {
      console.error('💥 JWT authentication error:', error);
      return res.status(500).json({ error: 'Authentication error' });
    }
  }
};

// Verify all methods are defined
console.log('✅ JWT Utilities loaded:');
console.log('   generateToken:', typeof jwtUtils.generateToken);
console.log('   verifyToken:', typeof jwtUtils.verifyToken);
console.log('   authenticateToken:', typeof jwtUtils.authenticateToken);

module.exports = jwtUtils;