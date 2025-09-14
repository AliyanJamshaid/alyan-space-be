const AUTH_MESSAGES = {
  SUCCESS: {
    LOGIN: "Login successful",
    LOGOUT: "Logout successful",
    TOKEN_REFRESHED: "Token refreshed successfully",
  },
  ERROR: {
    INVALID_CREDENTIALS: "Invalid email or password",
    USER_NOT_FOUND: "User not found",
    INVALID_TOKEN: "Invalid or expired token",
    TOKEN_REQUIRED: "Access token is required",
    REFRESH_TOKEN_REQUIRED: "Refresh token is required",

    UNAUTHORIZED: "Access denied. Admin privileges required.",
    ALREADY_AUTHENTICATED: "User already authenticated",
    SESSION_EXPIRED: "Session expired. Please login again.",
    RATE_LIMIT_EXCEEDED: "Too many requests. Please try again later.",
  },
  VALIDATION: {
    EMAIL_REQUIRED: "Email is required",
    EMAIL_INVALID: "Please provide a valid email address",
    PASSWORD_REQUIRED: "Password is required",
    PASSWORD_MIN_LENGTH: "Password must be at least 6 characters long",
  },
};

const AUTH_ROLES = {
  ADMIN: "admin",
};

const TOKEN_TYPES = {
  ACCESS: "access",
  REFRESH: "refresh",
};

module.exports = {
  AUTH_MESSAGES,
  AUTH_ROLES,
  TOKEN_TYPES,
};
