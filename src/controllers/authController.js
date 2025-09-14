const AuthService = require('../services/authService');
const logger = require('../config/logger');
const AUTH_CONFIG = require('../config/auth');
const { AUTH_MESSAGES } = require('../constants/auth');

class AuthController {
  /**
   * Login user
   * POST /api/auth/login
   */
  static async login(req, res) {
    try {
      const { email, password } = req.body;
      const ipAddress = req.ip || req.connection.remoteAddress;

      // Login through service
      const result = await AuthService.login(email, password, ipAddress);

      // Set refresh token as HTTP-only cookie
      res.cookie(
        AUTH_CONFIG.COOKIE.REFRESH_TOKEN_NAME,
        result.refreshToken,
        AUTH_CONFIG.COOKIE.OPTIONS
      );

      // Return success response
      res.status(200).json({
        success: true,
        message: AUTH_MESSAGES.SUCCESS.LOGIN,
        data: {
          user: result.user,
          accessToken: result.accessToken
        }
      });
    } catch (error) {
      logger.error('Login controller error:', {
        error: error.message,
        email: req.body.email,
        ip: req.ip
      });

      res.status(401).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * Refresh access token
   * POST /api/auth/refresh
   */
  static async refreshToken(req, res) {
    try {
      const refreshToken = req.cookies[AUTH_CONFIG.COOKIE.REFRESH_TOKEN_NAME];

      if (!refreshToken) {
        return res.status(401).json({
          success: false,
          error: AUTH_MESSAGES.ERROR.REFRESH_TOKEN_REQUIRED
        });
      }

      // Refresh token through service
      const result = await AuthService.refreshToken(refreshToken);

      // Set new refresh token as cookie
      res.cookie(
        AUTH_CONFIG.COOKIE.REFRESH_TOKEN_NAME,
        result.refreshToken,
        AUTH_CONFIG.COOKIE.OPTIONS
      );

      res.status(200).json({
        success: true,
        message: AUTH_MESSAGES.SUCCESS.TOKEN_REFRESHED,
        data: {
          user: result.user,
          accessToken: result.accessToken
        }
      });
    } catch (error) {
      logger.error('Token refresh controller error:', {
        error: error.message,
        ip: req.ip
      });

      // Clear invalid refresh token cookie
      res.clearCookie(AUTH_CONFIG.COOKIE.REFRESH_TOKEN_NAME);

      res.status(401).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * Logout user
   * POST /api/auth/logout
   */
  static async logout(req, res) {
    try {
      const refreshToken = req.cookies[AUTH_CONFIG.COOKIE.REFRESH_TOKEN_NAME];
      const userId = req.user?._id;

      // Logout through service
      await AuthService.logout(refreshToken, userId);

      // Clear refresh token cookie
      res.clearCookie(AUTH_CONFIG.COOKIE.REFRESH_TOKEN_NAME);

      res.status(200).json({
        success: true,
        message: AUTH_MESSAGES.SUCCESS.LOGOUT
      });
    } catch (error) {
      logger.error('Logout controller error:', {
        error: error.message,
        userId: req.user?._id,
        ip: req.ip
      });

      // Clear cookie even if logout fails
      res.clearCookie(AUTH_CONFIG.COOKIE.REFRESH_TOKEN_NAME);

      res.status(500).json({
        success: false,
        error: 'Logout failed'
      });
    }
  }

  /**
   * Logout from all devices
   * POST /api/auth/logout-all
   */
  static async logoutAll(req, res) {
    try {
      const userId = req.user._id;

      // Logout from all devices through service
      await AuthService.logoutAllDevices(userId);

      // Clear refresh token cookie
      res.clearCookie(AUTH_CONFIG.COOKIE.REFRESH_TOKEN_NAME);

      res.status(200).json({
        success: true,
        message: 'Logged out from all devices successfully'
      });
    } catch (error) {
      logger.error('Logout all controller error:', {
        error: error.message,
        userId: req.user?._id,
        ip: req.ip
      });

      res.status(500).json({
        success: false,
        error: 'Logout from all devices failed'
      });
    }
  }

  /**
   * Get user profile
   * GET /api/auth/profile
   */
  static async getProfile(req, res) {
    try {
      const userId = req.user._id;

      const profile = await AuthService.getProfile(userId);

      res.status(200).json({
        success: true,
        data: {
          user: profile
        }
      });
    } catch (error) {
      logger.error('Get profile controller error:', {
        error: error.message,
        userId: req.user?._id,
        ip: req.ip
      });

      res.status(404).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * Validate token
   * GET /api/auth/validate
   */
  static async validateToken(req, res) {
    try {
      // If we reach here, token is valid (middleware handled validation)
      res.status(200).json({
        success: true,
        data: {
          user: req.user,
          valid: true
        }
      });
    } catch (error) {
      logger.error('Validate token controller error:', {
        error: error.message,
        ip: req.ip
      });

      res.status(401).json({
        success: false,
        error: AUTH_MESSAGES.ERROR.INVALID_TOKEN,
        valid: false
      });
    }
  }

  /**
   * Get auth status
   * GET /api/auth/status
   */
  static async getAuthStatus(req, res) {
    try {
      const isAuthenticated = !!req.user;

      res.status(200).json({
        success: true,
        data: {
          isAuthenticated,
          user: req.user || null
        }
      });
    } catch (error) {
      logger.error('Auth status controller error:', {
        error: error.message,
        ip: req.ip
      });

      res.status(500).json({
        success: false,
        error: 'Failed to get auth status'
      });
    }
  }
}

module.exports = AuthController;