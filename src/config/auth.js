const AUTH_CONFIG = {
  JWT: {
    ACCESS_TOKEN_EXPIRY: '15m',
    REFRESH_TOKEN_EXPIRY: '7d',
    ALGORITHM: 'HS256'
  },
  BCRYPT: {
    SALT_ROUNDS: 12
  },
  RATE_LIMIT: {
    LOGIN_ATTEMPTS: 5,
    WINDOW_MS: 15 * 60 * 1000, // 15 minutes
    MESSAGE: 'Too many login attempts, please try again later.'
  },
  COOKIE: {
    REFRESH_TOKEN_NAME: 'refreshToken',
    OPTIONS: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    }
  },
  ADMIN_USER: {
    EMAIL: process.env.ADMIN_EMAIL || 'admin@alyanspace.com',
    PASSWORD: process.env.ADMIN_PASSWORD // Must be set in .env
  }
};

module.exports = AUTH_CONFIG;