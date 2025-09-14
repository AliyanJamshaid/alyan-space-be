const jwt = require('jsonwebtoken');
const AUTH_CONFIG = require('../config/auth');
const { TOKEN_TYPES } = require('../constants/auth');

class JWTService {
  /**
   * Generate access token
   * @param {Object} payload - Token payload
   * @returns {string} - JWT token
   */
  static generateAccessToken(payload) {
    try {
      return jwt.sign(
        {
          ...payload,
          type: TOKEN_TYPES.ACCESS
        },
        process.env.JWT_SECRET,
        {
          expiresIn: AUTH_CONFIG.JWT.ACCESS_TOKEN_EXPIRY,
          algorithm: AUTH_CONFIG.JWT.ALGORITHM
        }
      );
    } catch (error) {
      throw new Error('Failed to generate access token');
    }
  }

  /**
   * Generate refresh token
   * @param {Object} payload - Token payload
   * @returns {string} - JWT token
   */
  static generateRefreshToken(payload) {
    try {
      return jwt.sign(
        {
          ...payload,
          type: TOKEN_TYPES.REFRESH
        },
        process.env.JWT_REFRESH_SECRET,
        {
          expiresIn: AUTH_CONFIG.JWT.REFRESH_TOKEN_EXPIRY,
          algorithm: AUTH_CONFIG.JWT.ALGORITHM
        }
      );
    } catch (error) {
      throw new Error('Failed to generate refresh token');
    }
  }

  /**
   * Generate token pair (access + refresh)
   * @param {Object} user - User object
   * @returns {Object} - Token pair
   */
  static generateTokenPair(user) {
    const payload = {
      userId: user._id,
      email: user.email,
      role: user.role
    };

    return {
      accessToken: this.generateAccessToken(payload),
      refreshToken: this.generateRefreshToken(payload)
    };
  }

  /**
   * Verify access token
   * @param {string} token - JWT token
   * @returns {Object} - Decoded payload
   */
  static verifyAccessToken(token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      if (decoded.type !== TOKEN_TYPES.ACCESS) {
        throw new Error('Invalid token type');
      }

      return decoded;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new Error('Access token expired');
      }
      if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid access token');
      }
      throw error;
    }
  }

  /**
   * Verify refresh token
   * @param {string} token - JWT token
   * @returns {Object} - Decoded payload
   */
  static verifyRefreshToken(token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);

      if (decoded.type !== TOKEN_TYPES.REFRESH) {
        throw new Error('Invalid token type');
      }

      return decoded;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new Error('Refresh token expired');
      }
      if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid refresh token');
      }
      throw error;
    }
  }

  /**
   * Extract token from Authorization header
   * @param {string} authHeader - Authorization header value
   * @returns {string|null} - Extracted token
   */
  static extractTokenFromHeader(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }
    return authHeader.substring(7); // Remove 'Bearer ' prefix
  }

  /**
   * Get token expiry time
   * @param {string} token - JWT token
   * @returns {Date|null} - Expiry date
   */
  static getTokenExpiry(token) {
    try {
      const decoded = jwt.decode(token);
      return decoded?.exp ? new Date(decoded.exp * 1000) : null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Check if token is about to expire (within 2 minutes)
   * @param {string} token - JWT token
   * @returns {boolean} - Is expiring soon
   */
  static isTokenExpiringSoon(token) {
    const expiry = this.getTokenExpiry(token);
    if (!expiry) return true;

    const twoMinutesFromNow = new Date(Date.now() + 2 * 60 * 1000);
    return expiry <= twoMinutesFromNow;
  }
}

module.exports = JWTService;