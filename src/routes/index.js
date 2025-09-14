const express = require('express');
const authRoutes = require('./auth');

const router = express.Router();

// Health check endpoint
router.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'API is running',
    timestamp: new Date().toISOString()
  });
});

// Welcome endpoint
router.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Welcome to Alyan Space Backend API',
    version: '1.0.0'
  });
});

// Auth routes
router.use('/auth', authRoutes);

module.exports = router;