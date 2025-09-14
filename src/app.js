require("dotenv").config();
require("express-async-errors");

const express = require("express");
const morgan = require("morgan");
const helmet = require("helmet");
const compression = require("compression");
const cookieParser = require("cookie-parser");

const connectDB = require("./config/database");
const logger = require("./config/logger");
const corsMiddleware = require("./middleware/cors");
const errorHandler = require("./middleware/errorHandler");
const {
  apiRateLimiter,
  authRateLimiter,
  loginRateLimiter,
} = require("./middleware/rateLimiter");

const indexRoutes = require("./routes/index");

const app = express();

// Connect to database
connectDB();

// Trust proxy (for rate limiting behind reverse proxy)
app.set("trust proxy", 1);

// Security middleware
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);
app.use(compression());

// Rate limiting
app.use("/api", apiRateLimiter);
app.use("/api/auth", authRateLimiter);
app.use("/api/auth/login", loginRateLimiter);

// CORS
app.use(corsMiddleware);

// Logging
app.use(
  morgan("combined", {
    stream: {
      write: (message) => logger.info(message.trim()),
    },
    skip: (req) => req.url === "/api/health", // Skip health check logs
  })
);

// Body parsing
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// Cookie parsing
app.use(cookieParser());

// Routes
app.use("/api", indexRoutes);

// Error handling middleware (must be last)
app.use(errorHandler);

module.exports = app;
