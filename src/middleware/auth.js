const JWTService = require('../utils/jwt');
const User = require('../models/User');
const logger = require('../config/logger');
const { AUTH_MESSAGES, AUTH_ROLES } = require('../constants/auth');

/**
 * Authentication middleware - Verify JWT token
 */
const authenticate = async (req, res, next) => {
  try {
    // Extract token from Authorization header
    const authHeader = req.header('Authorization');
    const token = JWTService.extractTokenFromHeader(authHeader);

    if (!token) {
      return res.status(401).json({
        success: false,
        error: AUTH_MESSAGES.ERROR.TOKEN_REQUIRED
      });
    }

    // Verify token
    const decoded = JWTService.verifyAccessToken(token);

    // Find user and attach to request
    const user = await User.findById(decoded.userId);

    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        error: AUTH_MESSAGES.ERROR.UNAUTHORIZED
      });
    }

    // Attach user to request object
    req.user = user;
    req.token = token;

    next();
  } catch (error) {
    logger.error('Authentication error:', {
      error: error.message,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    return res.status(401).json({
      success: false,
      error: error.message === 'Access token expired'
        ? AUTH_MESSAGES.ERROR.SESSION_EXPIRED
        : AUTH_MESSAGES.ERROR.INVALID_TOKEN
    });
  }
};

/**
 * Authorization middleware - Check user role
 * @param {string|Array} roles - Required role(s)
 */
const authorize = (roles = []) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: AUTH_MESSAGES.ERROR.UNAUTHORIZED
      });
    }

    // Convert single role to array
    const requiredRoles = Array.isArray(roles) ? roles : [roles];

    // Check if user has required role
    if (requiredRoles.length && !requiredRoles.includes(req.user.role)) {
      logger.warn('Authorization failed:', {
        userId: req.user._id,
        userRole: req.user.role,
        requiredRoles,
        ip: req.ip
      });

      return res.status(403).json({
        success: false,
        error: AUTH_MESSAGES.ERROR.UNAUTHORIZED
      });
    }

    next();
  };
};

/**
 * Admin-only middleware
 */
const requireAdmin = authorize([AUTH_ROLES.ADMIN]);

/**
 * Optional authentication - Don't fail if no token
 */
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    const token = JWTService.extractTokenFromHeader(authHeader);

    if (token) {
      const decoded = JWTService.verifyAccessToken(token);
      const user = await User.findById(decoded.userId);

      if (user && user.isActive) {
        req.user = user;
        req.token = token;
      }
    }

    next();
  } catch (error) {
    // Continue without user if token is invalid
    next();
  }
};

/**
 * Check if user is already authenticated
 */
const checkAlreadyAuth = (req, res, next) => {
  const authHeader = req.header('Authorization');
  const token = JWTService.extractTokenFromHeader(authHeader);

  if (token) {
    try {
      const decoded = JWTService.verifyAccessToken(token);
      if (decoded) {
        return res.status(400).json({
          success: false,
          error: AUTH_MESSAGES.ERROR.ALREADY_AUTHENTICATED
        });
      }
    } catch (error) {
      // Token is invalid, continue with request
    }
  }

  next();
};

module.exports = {
  authenticate,
  authorize,
  requireAdmin,
  optionalAuth,
  checkAlreadyAuth
};