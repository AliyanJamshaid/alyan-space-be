const { body, validationResult } = require('express-validator');
const { AUTH_MESSAGES } = require('../constants/auth');

/**
 * Handle validation errors
 */
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    const errorMessages = errors.array().map(error => ({
      field: error.path,
      message: error.msg,
      value: error.value
    }));

    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errorMessages
    });
  }

  next();
};

/**
 * Login validation rules
 */
const loginValidation = [
  body('email')
    .isEmail()
    .withMessage(AUTH_MESSAGES.VALIDATION.EMAIL_INVALID)
    .normalizeEmail()
    .notEmpty()
    .withMessage(AUTH_MESSAGES.VALIDATION.EMAIL_REQUIRED),

  body('password')
    .notEmpty()
    .withMessage(AUTH_MESSAGES.VALIDATION.PASSWORD_REQUIRED)
    .isLength({ min: 6 })
    .withMessage(AUTH_MESSAGES.VALIDATION.PASSWORD_MIN_LENGTH),

  handleValidationErrors
];

/**
 * Email validation rules
 */
const emailValidation = [
  body('email')
    .isEmail()
    .withMessage(AUTH_MESSAGES.VALIDATION.EMAIL_INVALID)
    .normalizeEmail()
    .notEmpty()
    .withMessage(AUTH_MESSAGES.VALIDATION.EMAIL_REQUIRED),

  handleValidationErrors
];

/**
 * Strong password validation (for registration if needed in future)
 */
const strongPasswordValidation = [
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, one number and one special character'),

  handleValidationErrors
];

/**
 * Sanitize input to prevent XSS
 */
const sanitizeInput = (req, res, next) => {
  // Basic sanitization - in production, consider using a library like DOMPurify
  const sanitizeString = (str) => {
    if (typeof str !== 'string') return str;
    return str.trim().replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
  };

  // Sanitize request body
  if (req.body && typeof req.body === 'object') {
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string') {
        req.body[key] = sanitizeString(req.body[key]);
      }
    });
  }

  next();
};

module.exports = {
  loginValidation,
  emailValidation,
  strongPasswordValidation,
  sanitizeInput,
  handleValidationErrors
};