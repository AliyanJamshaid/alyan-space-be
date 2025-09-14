const express = require('express');
const router = express.Router();

router.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'API is running',
    timestamp: new Date().toISOString()
  });
});

router.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Welcome to Alyan Space Backend API',
    version: '1.0.0'
  });
});

module.exports = router;