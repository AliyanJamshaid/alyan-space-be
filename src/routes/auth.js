const express = require('express');
const AuthController = require('../controllers/authController');
const { authenticate, checkAlreadyAuth, optionalAuth } = require('../middleware/auth');
const { loginValidation, sanitizeInput } = require('../utils/validation');

const router = express.Router();

// Apply sanitization to all routes
router.use(sanitizeInput);

/**
 * @route   POST /api/auth/login
 * @desc    Login user
 * @access  Public
 */
router.post('/login',
  checkAlreadyAuth,
  loginValidation,
  AuthController.login
);

/**
 * @route   POST /api/auth/refresh
 * @desc    Refresh access token using refresh token
 * @access  Public (requires refresh token in cookies)
 */
router.post('/refresh', AuthController.refreshToken);

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user (clear refresh token)
 * @access  Private
 */
router.post('/logout', optionalAuth, AuthController.logout);

/**
 * @route   POST /api/auth/logout-all
 * @desc    Logout from all devices
 * @access  Private
 */
router.post('/logout-all', authenticate, AuthController.logoutAll);

/**
 * @route   GET /api/auth/profile
 * @desc    Get user profile
 * @access  Private
 */
router.get('/profile', authenticate, AuthController.getProfile);

/**
 * @route   GET /api/auth/validate
 * @desc    Validate access token
 * @access  Private
 */
router.get('/validate', authenticate, AuthController.validateToken);

/**
 * @route   GET /api/auth/status
 * @desc    Get authentication status
 * @access  Public (optional auth)
 */
router.get('/status', optionalAuth, AuthController.getAuthStatus);

module.exports = router;