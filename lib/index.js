import { LRUCache } from "lru-cache";

const SQL_INJECTION_PATTERNS = [
  /(\%27)|(\')|(\-\-)|(\%23)|(#)/gi,
  /(\b(OR|AND)\b.*?=\s*?\1.*?)/gi,
  /\b(SELECT|INSERT|DELETE|UPDATE|UNION|DROP|ALTER)\b/gi,
  /(;|\s*--|\/\*|\*\/)/gi,
  /(\bWHERE\b|\bHAVING\b|\bGROUP\b|\bORDER\b)/gi,
  /' OR '.*?'/gi,
  /" OR ".*?"/gi,
  /' AND '.*?'/gi,
  /" AND ".*?"/gi,
  /\b(0x[0-9A-F]+)\b/gi,
  /(\bWAITFOR\b|\bSLEEP\b)/gi,
  /(\bMID\b|\bVERSION\b)/gi,
  /(\bINTO\b|@|@@)/gi,             
  /\b(ALL|ANY|SOME)\b/gi,
  /(\%00)/gi                          
];

function detectSqlInjection(input) {
  if (typeof input !== 'string' || input.trim() === '') {
    return false;
  }
  return SQL_INJECTION_PATTERNS.some(pattern => pattern.test(input));
}

// IP-based rate limiting cache with persistent blocking
const attackCache = new LRUCache({
  max: 1000,
  ttl: 1000 * 60 * 60 // 1-hour block for persistent offenders
});

function sqlid(req, res, next) {
  try {
    const clientIp = req.ip || req.connection.remoteAddress;
    if (attackCache.has(clientIp)) {
      return res.status(403).json({
        error: 'Access permanently blocked due to repeated suspicious activities.',
        blockedUntil: 'Indefinite'
      });
    }
    const inputs = [
      req.body?.input,
      req.query?.input,
      req.params?.input,
      ...(Object.values(req.body || {})),
      ...(Object.values(req.query || {})),
      ...(Object.values(req.params || {}))
    ].filter(input => input !== undefined);

    const hasSqlInjection = inputs.some(input => 
      detectSqlInjection(String(input))
    );
    if (hasSqlInjection) {
      const ipData = attackCache.get(clientIp) || { 
        attempts: 0, 
        lastDetectionTime: Date.now() 
      };
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