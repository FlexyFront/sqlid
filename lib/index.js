import { LRUCache } from "lru-cache";

// Comprehensive SQL injection detection patterns
const SQL_INJECTION_PATTERNS = [
  /(\%27)|(\')|(\-\-)|(\%23)|(#)/gi,  // Match ' or -- or #
  /(\b(OR|AND)\b.*?=\s*?\1.*?)/gi,    // Match OR/AND ... = ...
  /\b(SELECT|INSERT|DELETE|UPDATE|UNION|DROP|ALTER)\b/gi, // Match SQL keywords
  /(;|\s*--|\/\*|\*\/)/gi,            // Match comment styles
  /(\bWHERE\b|\bHAVING\b|\bGROUP\b|\bORDER\b)/gi, // Match other SQL clauses
  /' OR '.*?'/gi,                     // Common ' OR ' pattern
  /" OR ".*?"/gi,                     // Common " OR " pattern
  /' AND '.*?'/gi,                    // Common ' AND ' pattern
  /" AND ".*?"/gi,                    // Common " AND " pattern
  /\b(0x[0-9A-F]+)\b/gi,              // Match hexadecimal values
  /(\bWAITFOR\b|\bSLEEP\b)/gi,        // Match time-based attacks
  /(\bMID\b|\bVERSION\b)/gi,          // Match version checks and substring patterns
  /(\bINTO\b|@|@@)/gi,                // Match variable assignments
  /\b(ALL|ANY|SOME)\b/gi,             // Match ALL, ANY, SOME
  /(\%00)/gi                          // Match null byte
];

// Robust SQL injection detection function
function detectSqlInjection(input) {
  // Immediately return false for non-string or empty inputs
  if (typeof input !== 'string' || input.trim() === '') {
    return false;
  }

  // Check against all injection patterns
  return SQL_INJECTION_PATTERNS.some(pattern => pattern.test(input));
}

// IP-based rate limiting cache with persistent blocking
const attackCache = new LRUCache({
  max: 1000,
  ttl: 1000 * 60 * 60 // 1-hour block for persistent offenders
});

// Middleware for SQL injection protection
function sqlid(req, res, next) {
  try {
    // Get client IP
    const clientIp = req.ip || req.connection.remoteAddress;

    // Check if IP is permanently blocked
    if (attackCache.has(clientIp)) {
      return res.status(403).json({
        error: 'Access permanently blocked due to repeated suspicious activities.',
        blockedUntil: 'Indefinite'
      });
    }

    // Collect all potential input sources
    const inputs = [
      req.body?.input,
      req.query?.input,
      req.params?.input,
      ...(Object.values(req.body || {})),
      ...(Object.values(req.query || {})),
      ...(Object.values(req.params || {}))
    ].filter(input => input !== undefined);

    // Detect SQL injection in any input
    const hasSqlInjection = inputs.some(input => 
      detectSqlInjection(String(input))
    );

    // If SQL injection detected
    if (hasSqlInjection) {
      // Get or initialize attack tracking for this IP
      const ipData = attackCache.get(clientIp) || { 
        attempts: 0, 
        lastDetectionTime: Date.now() 
      };

      // Increment attempts
      ipData.attempts++;
      ipData.lastDetectionTime = Date.now();

      // Permanent block after 5 attempts
      if (ipData.attempts >= 5) {
        attackCache.set(clientIp, ipData);
        return res.status(403).json({
          error: 'Permanent access block due to repeated SQL injection attempts.',
          blockedUntil: 'Indefinite'
        });
      }

      // Temporary block with escalating restrictions
      attackCache.set(clientIp, ipData, { 
        ttl: Math.pow(2, ipData.attempts) * 60 * 1000 // Exponential backoff
      });

      return res.status(403).json({
        error: 'Potential SQL injection detected. Request blocked.',
        remainingAttempts: 5 - ipData.attempts,
        nextAttemptDelay: Math.pow(2, ipData.attempts) // minutes
      });
    }

    // Proceed if no injection is detected
    next();

  } catch (error) {
    console.error('SQL Injection Middleware Error:', error);
    res.status(500).json({ 
      error: 'Internal server error', 
      message: 'Unable to process request' 
    });
  }
}

export default sqlid;