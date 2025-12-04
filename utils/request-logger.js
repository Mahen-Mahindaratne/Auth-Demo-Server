class RequestLogger {
  constructor() {
    this.requests = [];
    this.maxLogSize = 10000; // Keep last 10,000 requests
  }

  middleware() {
    return (req, res, next) => {
      const startTime = Date.now();
      const requestId = Math.random().toString(36).substring(2, 15);
      
      // Store request info
      req.requestId = requestId;
      
      // Log response finish
      res.on('finish', () => {
        const duration = Date.now() - startTime;
        
        const logEntry = {
          id: requestId,
          timestamp: new Date().toISOString(),
          method: req.method,
          url: req.url,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          statusCode: res.statusCode,
          duration,
          username: req.user?.username || req.jwtUser?.username || 'anonymous'
        };
        
        this.requests.push(logEntry);
        
        // Maintain log size
        if (this.requests.length > this.maxLogSize) {
          this.requests = this.requests.slice(-this.maxLogSize);
        }
      });
      
      next();
    };
  }

  logError(req, error) {
    const errorEntry = {
      timestamp: new Date().toISOString(),
      method: req.method,
      url: req.url,
      ip: req.ip,
      error: error.message,
      stack: error.stack,
      username: req.user?.username || req.jwtUser?.username || 'anonymous'
    };
    
    console.error('🚨 Error logged:', errorEntry);
  }

  getStats() {
    const now = Date.now();
    const oneHourAgo = now - (60 * 60 * 1000);
    
    const recentRequests = this.requests.filter(req => 
      new Date(req.timestamp).getTime() > oneHourAgo
    );
    
    const endpointStats = {};
    this.requests.forEach(req => {
      const endpoint = req.url.split('?')[0];
      endpointStats[endpoint] = (endpointStats[endpoint] || 0) + 1;
    });
    
    const errorCount = this.requests.filter(req => req.statusCode >= 400).length;
    const totalRequests = this.requests.length;
    
    return {
      totalRequests,
      requestsLastHour: recentRequests.length,
      endpointStats,
      errorRate: totalRequests > 0 ? (errorCount / totalRequests) * 100 : 0
    };
  }

  getDetailedAnalytics() {
    const now = Date.now();
    const oneDayAgo = now - (24 * 60 * 60 * 1000);
    
    const dayRequests = this.requests.filter(req => 
      new Date(req.timestamp).getTime() > oneDayAgo
    );
    
    const endpoints = {};
    const errors = [];
    let totalDuration = 0;
    
    dayRequests.forEach(req => {
      // Endpoint stats
      const endpoint = req.method + ' ' + req.url.split('?')[0];
      if (!endpoints[endpoint]) {
        endpoints[endpoint] = { count: 0, totalDuration: 0, errors: 0 };
      }
      endpoints[endpoint].count++;
      endpoints[endpoint].totalDuration += req.duration;
      
      // Error tracking
      if (req.statusCode >= 400) {
        endpoints[endpoint].errors++;
        errors.push({
          timestamp: req.timestamp,
          endpoint: req.url,
          statusCode: req.statusCode,
          method: req.method
        });
      }
      
      totalDuration += req.duration;
    });
    
    // Calculate averages
    Object.keys(endpoints).forEach(endpoint => {
      endpoints[endpoint].avgDuration = 
        endpoints[endpoint].totalDuration / endpoints[endpoint].count;
    });
    
    return {
      summary: {
        totalRequests: dayRequests.length,
        uniqueEndpoints: Object.keys(endpoints).length,
        avgResponseTime: dayRequests.length > 0 ? totalDuration / dayRequests.length : 0,
        errorCount: errors.length
      },
      endpoints,
      errors: errors.slice(-50), // Last 50 errors
      performance: {
        p95: this.calculatePercentile(dayRequests.map(r => r.duration), 95),
        p99: this.calculatePercentile(dayRequests.map(r => r.duration), 99)
      }
    };
  }

  calculatePercentile(values, percentile) {
    if (values.length === 0) return 0;
    
    values.sort((a, b) => a - b);
    const index = (percentile / 100) * (values.length - 1);
    const lower = Math.floor(index);
    const upper = Math.ceil(index);
    
    if (lower === upper) return values[lower];
    return (values[lower] + values[upper]) / 2;
  }
}

module.exports = RequestLogger;