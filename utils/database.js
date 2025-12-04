const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const envConfig = require('../config/environment');

class MemoryDatabase {
  constructor() {
    this.users = new Map();
    this.sessions = new Map();
    this.failedAttempts = new Map();
    this.jwtTokens = new Map();
    this.initUsers();
  }

  async initUsers() {
    console.log('🔄 Initializing users from environment...');
    
    for (const userConfig of envConfig.PARSED_USERS) {
      try {
        const passwordHash = await bcrypt.hash(userConfig.password, 12);
        const keyFileHash = userConfig.keyFile ? this.generateHash(userConfig.keyFile) : null;

        this.users.set(userConfig.username, {
          id: Date.now() + Math.random(),
          username: userConfig.username,
          password_hash: passwordHash,
          key_file_hash: keyFileHash,
          failed_login_attempts: 0,
          account_locked_until: null,
          created_at: new Date(),
          description: userConfig.description,
          roles: userConfig.username === 'admin' ? ['admin', 'user'] : ['user']
        });

        console.log(`   👤 ${userConfig.username} - ${userConfig.description}`);
      } catch (error) {
        console.error(`❌ Error creating user ${userConfig.username}:`, error);
      }
    }

    console.log(`✅ Successfully created ${this.users.size} users`);
  }

  generateHash(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  async getUserByUsername(username) {
    return this.users.get(username) || null;
  }

  async createSession(sessionId, username, keyValidated = false) {
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    this.sessions.set(sessionId, {
      session_id: sessionId,
      username: username,
      key_validated: keyValidated,
      created_at: new Date(),
      expires_at: expiresAt
    });
  }

  async getSession(sessionId) {
    const session = this.sessions.get(sessionId);
    if (session && session.expires_at > new Date()) {
      return session;
    }
    return null;
  }

  async deleteSession(sessionId) {
    this.sessions.delete(sessionId);
  }

  recordFailedAttempt(ip, username) {
    const key = `${ip}-${username}`;
    const now = Date.now();
    const windowMs = envConfig.RATE_LIMIT_WINDOW_MS;
    
    if (!this.failedAttempts.has(key)) {
      this.failedAttempts.set(key, []);
    }
    
    const attempts = this.failedAttempts.get(key);
    const recentAttempts = attempts.filter(time => now - time < windowMs);
    recentAttempts.push(now);
    this.failedAttempts.set(key, recentAttempts);
    
    return recentAttempts.length;
  }

  getFailedAttemptsCount(ip, username) {
    const key = `${ip}-${username}`;
    const attempts = this.failedAttempts.get(key) || [];
    const now = Date.now();
    const windowMs = envConfig.RATE_LIMIT_WINDOW_MS;
    
    return attempts.filter(time => now - time < windowMs).length;
  }

  resetFailedAttempts(ip, username) {
    const key = `${ip}-${username}`;
    this.failedAttempts.delete(key);
  }

  // JWT token management
  async storeJWTToken(token, username) {
    if (!envConfig.ENABLE_JWT) return;
    
    const decoded = require('jsonwebtoken').decode(token);
    this.jwtTokens.set(decoded.jti, {
      username,
      createdAt: new Date(),
      expiresAt: new Date(decoded.exp * 1000)
    });
  }

  async isValidJWTToken(tokenId) {
    if (!envConfig.ENABLE_JWT) return false;
    
    const tokenData = this.jwtTokens.get(tokenId);
    if (!tokenData) return false;
    
    if (tokenData.expiresAt < new Date()) {
      this.jwtTokens.delete(tokenId);
      return false;
    }
    
    return true;
  }

  // Debug information
  debug() {
    return {
      users: Array.from(this.users.entries()).map(([username, user]) => ({
        username,
        requiresKey: !!user.key_file_hash,
        description: user.description
      })),
      sessions: this.sessions.size,
      failedAttempts: this.failedAttempts.size,
      jwtTokens: this.jwtTokens.size
    };
  }
}

module.exports = MemoryDatabase;