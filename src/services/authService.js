const User = require("../models/User");
const JWTService = require("../utils/jwt");
const logger = require("../config/logger");
const AUTH_CONFIG = require("../config/auth");
const { AUTH_MESSAGES } = require("../constants/auth");

class AuthService {
  /**
   * Login user with email and password
   * @param {string} email - User email
   * @param {string} password - User password
   * @param {string} ipAddress - Client IP address
   * @returns {Object} - User data and tokens
   */
  static async login(email, password, ipAddress) {
    try {
      // Check if this is the admin user
      if (email !== AUTH_CONFIG.ADMIN_USER.EMAIL) {
        logger.warn("Invalid login attempt - wrong email:", {
          attemptedEmail: email,
          ip: ipAddress,
        });
        throw new Error(AUTH_MESSAGES.ERROR.INVALID_CREDENTIALS);
      }

      // For single admin user, check against environment password
      if (!AUTH_CONFIG.ADMIN_USER.PASSWORD) {
        logger.error("Admin password not configured in environment");
        throw new Error("Authentication system misconfigured");
      }

      // Find or create admin user
      let user = await User.findByEmailWithPassword(email);

      if (!user) {
        // Create admin user if doesn't exist
        user = new User({
          email: AUTH_CONFIG.ADMIN_USER.EMAIL,
          password: AUTH_CONFIG.ADMIN_USER.PASSWORD,
          role: "admin",
        });
        await user.save();

        // Fetch user again to get the clean version
        user = await User.findByEmailWithPassword(email);
      }

      // Verify password
      const isPasswordValid = await user.comparePassword(password);
      if (!isPasswordValid) {
        logger.warn("Invalid login attempt - wrong password:", {
          email,
          ip: ipAddress,
        });
        throw new Error(AUTH_MESSAGES.ERROR.INVALID_CREDENTIALS);
      }

      // Generate token pair
      const { accessToken, refreshToken } = JWTService.generateTokenPair(user);

      // Store refresh token in database
      await user.addRefreshToken(refreshToken);
      await user.updateLastLogin();

      // Remove password from user object
      const userResponse = user.toJSON();

      logger.info("User logged in successfully:", {
        userId: user._id,
        email: user.email,
        ip: ipAddress,
      });

      return {
        user: userResponse,
        accessToken,
        refreshToken,
      };
    } catch (error) {
      logger.error("Login service error:", {
        error: error.message,
        email,
        ip: ipAddress,
      });
      throw error;
    }
  }

  /**
   * Refresh access token using refresh token
   * @param {string} refreshToken - Refresh token
   * @returns {Object} - New token pair
   */
  static async refreshToken(refreshToken) {
    try {
      // Verify refresh token
      const decoded = JWTService.verifyRefreshToken(refreshToken);

      // Find user and check if refresh token exists
      const user = await User.findById(decoded.userId);

      if (!user || !user.isActive) {
        throw new Error(AUTH_MESSAGES.ERROR.USER_NOT_FOUND);
      }

      // Check if refresh token exists in database
      const tokenExists = user.refreshTokens.some(
        (token) => token.token === refreshToken
      );

      if (!tokenExists) {
        throw new Error(AUTH_MESSAGES.ERROR.INVALID_TOKEN);
      }

      // Generate new token pair
      const tokens = JWTService.generateTokenPair(user);

      // Remove old refresh token and add new one
      await user.removeRefreshToken(refreshToken);
      await user.addRefreshToken(tokens.refreshToken);

      logger.info("Token refreshed successfully:", {
        userId: user._id,
        email: user.email,
      });

      return {
        user: user.toJSON(),
        ...tokens,
      };
    } catch (error) {
      logger.error("Token refresh error:", {
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Logout user by removing refresh token
   * @param {string} refreshToken - Refresh token to remove
   * @param {string} userId - User ID
   */
  static async logout(refreshToken, userId) {
    try {
      const user = await User.findById(userId);

      if (user && refreshToken) {
        await user.removeRefreshToken(refreshToken);
      }

      logger.info("User logged out successfully:", {
        userId,
      });
    } catch (error) {
      logger.error("Logout service error:", {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Logout from all devices by removing all refresh tokens
   * @param {string} userId - User ID
   */
  static async logoutAllDevices(userId) {
    try {
      const user = await User.findById(userId);

      if (user) {
        await user.removeAllRefreshTokens();
      }

      logger.info("User logged out from all devices:", {
        userId,
      });
    } catch (error) {
      logger.error("Logout all devices error:", {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Get user profile
   * @param {string} userId - User ID
   * @returns {Object} - User profile
   */
  static async getProfile(userId) {
    try {
      const user = await User.findById(userId);

      if (!user || !user.isActive) {
        throw new Error(AUTH_MESSAGES.ERROR.USER_NOT_FOUND);
      }

      return user.toJSON();
    } catch (error) {
      logger.error("Get profile error:", {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Validate token and return user
   * @param {string} token - Access token
   * @returns {Object} - User data
   */
  static async validateToken(token) {
    try {
      const decoded = JWTService.verifyAccessToken(token);
      const user = await User.findById(decoded.userId);

      if (!user || !user.isActive) {
        throw new Error(AUTH_MESSAGES.ERROR.USER_NOT_FOUND);
      }

      return user.toJSON();
    } catch (error) {
      throw error;
    }
  }

  /**
   * Clean up expired refresh tokens (maintenance function)
   */
  static async cleanupExpiredTokens() {
    try {
      // MongoDB will automatically remove expired tokens due to TTL index
      // This is just for manual cleanup if needed
      const result = await User.updateMany(
        {},
        {
          $pull: {
            refreshTokens: {
              createdAt: {
                $lt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // 7 days ago
              },
            },
          },
        }
      );

      logger.info("Expired tokens cleaned up:", {
        modifiedCount: result.modifiedCount,
      });

      return result;
    } catch (error) {
      logger.error("Token cleanup error:", {
        error: error.message,
      });
      throw error;
    }
  }
}

module.exports = AuthService;
