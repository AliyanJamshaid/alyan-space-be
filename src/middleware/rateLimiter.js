const rateLimit = require('express-rate-limit');
const AUTH_CONFIG = require('../config/auth');
const logger = require('../config/logger');

/**
 * Rate limiter for authentication endpoints
 */
const authRateLimiter = rateLimit({
  windowMs: 2 * 60 * 1000, // 2 minutes (more lenient for development)
  max: 50, // Much higher limit for development
  message: {
    success: false,
    error: AUTH_CONFIG.RATE_LIMIT.MESSAGE
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('Rate limit exceeded for auth endpoint:', {
      ip: req.ip,
      url: req.url,
      userAgent: req.get('User-Agent')
    });

    res.status(429).json({
      success: false,
      error: AUTH_CONFIG.RATE_LIMIT.MESSAGE,
      retryAfter: Math.ceil(2 * 60) // 2 minutes
    });
  },
  skip: (req) => {
    // Skip rate limiting for health checks and in development
    return req.path === '/health' || process.env.NODE_ENV === 'development';
  }
});

/**
 * Strict rate limiter for login endpoint specifically
 */
const loginRateLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10, // More lenient for development
  message: {
    success: false,
    error: 'Too many login attempts from this IP, please try again in 5 minutes.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('Login rate limit exceeded:', {
      ip: req.ip,
      email: req.body?.email,
      userAgent: req.get('User-Agent')
    });

    res.status(429).json({
      success: false,
      error: 'Too many login attempts from this IP, please try again in 5 minutes.',
      retryAfter: Math.ceil(5 * 60) // 5 minutes
    });
  },
  skip: (req) => {
    // Skip in development environment
    return process.env.NODE_ENV === 'development';
  }
});

/**
 * General API rate limiter
 */
const apiRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // More generous for general API usage
  message: {
    success: false,
    error: 'Too many API requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('API rate limit exceeded:', {
      ip: req.ip,
      url: req.url,
      userAgent: req.get('User-Agent')
    });

    res.status(429).json({
      success: false,
      error: 'Too many API requests from this IP, please try again later.',
      retryAfter: 900 // 15 minutes
    });
  }
});

/**
 * Create custom rate limiter
 * @param {Object} options - Rate limiter options
 */
const createRateLimiter = (options) => {
  const defaultOptions = {
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: {
      success: false,
      error: 'Too many requests from this IP, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false
  };

  return rateLimit({ ...defaultOptions, ...options });
};

module.exports = {
  authRateLimiter,
  loginRateLimiter,
  apiRateLimiter,
  createRateLimiter
};