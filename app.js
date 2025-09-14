require('dotenv').config();
require('express-async-errors');

const express = require('express');
const morgan = require('morgan');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');

const connectDB = require('./config/database');
const logger = require('./config/logger');
const corsMiddleware = require('./middleware/cors');
const errorHandler = require('./middleware/errorHandler');

const indexRoutes = require('./routes/index');

const app = express();

connectDB();

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});

app.use(helmet());
app.use(compression());
app.use(limiter);
app.use(corsMiddleware);
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

app.use('/api', indexRoutes);

app.use(errorHandler);

module.exports = app;