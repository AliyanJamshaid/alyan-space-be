const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'warn', // Only show warnings and errors by default
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.simple() // Simpler format
  ),
  transports: [
    // Only console logging in development
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ level, message, timestamp }) => {
          return `${level}: ${message}`;
        })
      )
    })
  ]
});

module.exports = logger;